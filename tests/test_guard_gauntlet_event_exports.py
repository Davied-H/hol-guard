"""Tests for how exported host events mark the end of an agent session."""

from ci.gauntlet.evidence import public_events

AWAITING_JOB = {"type": "agent_end", "isTerminal": False, "yielded": True, "awaitingAsyncWork": True}


def ends(events):
    return [event["terminal"] for event in public_events(events, {}) if event["type"] == "agent_end"]


def test_terminal_end_is_terminal():
    assert ends([{"type": "agent_end", "isTerminal": True}]) == [True]


def test_final_end_awaiting_only_a_background_job_is_terminal():
    """A dev server left running does not keep a finished print session open."""
    assert ends([{"type": "message_end", "message": {"role": "assistant"}}, AWAITING_JOB]) == [True]


def test_end_awaiting_a_job_that_wakes_the_agent_is_not_terminal():
    later = [{"type": "agent_start"}, {"type": "agent_end", "isTerminal": True}]
    assert ends([AWAITING_JOB, *later]) == [False, True]


def test_continuations_the_agent_scheduled_are_not_terminal():
    retry = {"type": "agent_end", "isTerminal": False, "yielded": False}
    queued = {"type": "agent_end", "isTerminal": False, "yielded": True}
    unyielded_job = {**AWAITING_JOB, "yielded": False}
    assert ends([retry]) == ends([queued]) == ends([unyielded_job]) == [False]
