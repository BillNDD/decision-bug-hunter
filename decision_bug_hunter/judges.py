"""The judge registry: which decision model DBH asks, and by which routes.

A judge is one decision model. A route is one way to reach it. The pairing is
fixed data here and nothing else: this module imports no adapter, so the CLI,
``providers.make_provider`` and the Tile Sieve threshold loader can all use it
without an import cycle.

``openai``
    OpenAI Decisions (``gpt-6-luna``), directly (``openai``) or through
    OpenRouter (``openrouter``). Both routes are verified live.

``microsoft``
    Microsoft-Decision-1, through OpenRouter (``openrouter``) or Microsoft
    Foundry (``foundry``). The OpenRouter route was verified live on
    2026-10-11. The Foundry route is built from Microsoft's documentation and
    is not yet verified live; the deployment name is the model there, so its
    entry carries no model id.

Report, receipt and handoff fields name the judge only when it is not OpenAI;
an absent judge means OpenAI.
"""
from __future__ import annotations

from dataclasses import dataclass

from .protocol import ProviderError


@dataclass(frozen=True)
class JudgeRoute:
    """One (judge, route) pair."""

    #: The ``--provider`` value: ``openai``, ``openrouter`` or ``foundry``.
    selector: str
    #: The adapter's route name, as in receipts and reports.
    route_name: str
    #: The allow-listed model id; None where the deployment name is the model.
    model: str | None
    verified_live: bool


@dataclass(frozen=True)
class JudgeSpec:
    id: str
    title: str
    routes: tuple[JudgeRoute, ...]
    #: One line the command line prints to stderr, once, before a run with this
    #: judge starts; None for a judge that needs no notice.
    notice: str | None = None


JUDGES = {
    "openai": JudgeSpec(
        "openai", "OpenAI Decisions (gpt-6-luna)",
        (JudgeRoute("openai", "openai-decisions", "gpt-6-luna", True),
         JudgeRoute("openrouter", "openrouter-decisions", "openai/gpt-6-luna-decisions",
                    True))),
    "microsoft": JudgeSpec(
        "microsoft", "Microsoft-Decision-1",
        (JudgeRoute("openrouter", "openrouter-decisions", "microsoft/microsoft-decision-1",
                    True),
         JudgeRoute("foundry", "foundry-decisions", None, False)),
        notice=("Note: Microsoft-Decision-1 support is experimental: in DBH's validation it "
                "finds fewer bugs than OpenAI Decisions (README: Choosing a judge).")),
}
JUDGE_CHOICES = ("openai", "microsoft")


def judge_route(judge: str, selector: str) -> JudgeRoute:
    """The route of *judge* chosen by *selector*, else ``invalid_request``.

    An unknown judge, an unknown selector and a pair outside the registry
    (such as ``microsoft`` with ``openai``) are all the same refusal.
    """
    spec = JUDGES.get(judge) if type(judge) is str else None
    if spec is not None and type(selector) is str:
        for route in spec.routes:
            if route.selector == selector:
                return route
    raise ProviderError("invalid_request")


def judge_of_model(route_name: str, model_id: str | None) -> str | None:
    """The judge that serves *model_id* on *route_name*, or None.

    A route entry without a model id (Foundry) matches any deployment name.
    """
    for judge in JUDGE_CHOICES:
        for route in JUDGES[judge].routes:
            if route.route_name == route_name and (route.model is None
                                                   or route.model == model_id):
                return judge
    return None
