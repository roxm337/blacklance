"""Blackboard acknowledgement tracking.

`ack()` was a `pass`. Nothing called it, so a reader could not tell a message
it had already handled from one it had never seen, and `to_dict` dropped the
distinction on save. These tests pin the contract: first ack wins, later ones
are no-ops, `pending()` hides consumed messages, and the saved payload keeps
the timestamp.
"""

from agents.blackboard import AgentRole, Blackboard


def _board():
    return Blackboard(object(), {})


def test_ack_is_first_wins_and_idempotent():
    board = _board()
    msg = board.send(AgentRole.SUPERVISOR, AgentRole.EXPLOITATION,
                     "task_assigned", {"task": "probe"})

    assert board.ack(msg) is True
    first = msg.acknowledged_at
    assert first > 0
    assert board.ack(msg) is False
    assert msg.acknowledged_at == first


def test_pending_filters_only_unacknowledged_for_target():
    board = _board()
    a = board.send(AgentRole.SUPERVISOR, AgentRole.EXPLOITATION,
                   "task_assigned", {"n": 1})
    b = board.send(AgentRole.SUPERVISOR, AgentRole.EXPLOITATION,
                   "task_assigned", {"n": 2})
    board.send(AgentRole.SUPERVISOR, AgentRole.VERIFICATION,
               "task_assigned", {"n": 3})

    assert board.pending(AgentRole.EXPLOITATION) == [a, b]
    board.ack(a)
    assert board.pending(AgentRole.EXPLOITATION) == [b]
    assert len(board.pending(AgentRole.EXPLOITATION, "task_assigned")) == 1
    assert board.pending(AgentRole.EXPLOITATION, "result") == []


def test_serialization_keeps_ack_state_and_counts():
    board = _board()
    a = board.send(AgentRole.SUPERVISOR, AgentRole.EXPLOITATION,
                   "task_assigned", {"n": 1})
    board.send(AgentRole.SUPERVISOR, AgentRole.EXPLOITATION,
               "task_assigned", {"n": 2})
    board.ack(a)

    payload = board.to_dict()
    acks = [m["acknowledged_at"] for m in payload["messages"]]
    assert acks[0] == a.acknowledged_at > 0
    assert acks[1] == 0
    assert payload["stats"]["unacknowledged"] == 1
