
"""
Lab 11 — Main Entry Point

Chạy từ gốc repo:

    python src/main.py
    python src/main.py --part 2
    python src/main.py --part 3
    python src/main.py --part 4

Checkpoint:
    --part 2 → Guardrails
    --part 3 → Pipeline / results.json
    --part 4 → Red Team

File JSON luôn ghi vào:
    <repo>/outputs/

Tham khảo:
    src/testing/
    src/hitl/
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


# ============================================================
# PATH CONFIGURATION
# ============================================================

# src/
_SRC_DIR = Path(__file__).resolve().parent

# repo/
_REPO_DIR = _SRC_DIR.parent

# Đảm bảo import được:
#   core
#   guardrails
#   assignment
#   agents
#   attacks
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))


# ============================================================
# CORE
# ============================================================

from core.config import setup_api_key


# ============================================================
# CHECKPOINT 2
# ============================================================

async def part2_guardrails():
    """
    Checkpoint 2:
        Input Guardrails
        Output Guardrails
    """

    print("\n" + "=" * 60)
    print("CHECKPOINT 2: Guardrails")
    print("=" * 60)

    # --------------------------------------------------------
    # Input Guardrails
    # --------------------------------------------------------

    print("\n--- Input Guardrails ---")

    from guardrails.input_guardrails import (
        test_injection_detection,
        test_topic_filter,
        test_input_plugin,
    )

    print("\n[1] Injection detection")
    test_injection_detection()

    print("\n[2] Topic filter")
    test_topic_filter()

    print("\n[3] Input Guardrail Plugin")
    await test_input_plugin()

    # --------------------------------------------------------
    # Output Guardrails
    # --------------------------------------------------------

    print("\n--- Output Guardrails ---")

    from guardrails.output_guardrails import (
        test_content_filter,
    )

    print("\n[1] Content filter")
    test_content_filter()

    print(
        "\n[2] LLM-as-Judge / NeMo"
        "\n    Optional — skipped"
    )

    print("\nCheckpoint 2 completed.")


# ============================================================
# CHECKPOINT 3
# ============================================================

async def part3_assignment_suite():
    """
    Checkpoint 3:
        Rate Limit
        Input Guardrail
        Output Guardrail
        Audit Log
        Monitoring
        Egress
        Results JSON
    """

    print("\n" + "=" * 60)
    print("CHECKPOINT 3: Assignment suite")
    print("Output: outputs/*.json")
    print("=" * 60)

    try:

        from assignment.pipeline import (
            build_production_plugins,
            build_observability,
            run_assignment_suite,
        )

        # ----------------------------------------------------
        # Build production plugins
        # ----------------------------------------------------

        print("\n[1] Building production plugins...")

        plugins = build_production_plugins(
            use_llm_judge=False
        )

        print(
            "    Plugin order:"
        )

        for index, plugin in enumerate(
            plugins,
            start=1,
        ):
            plugin_name = getattr(
                plugin,
                "name",
                plugin.__class__.__name__,
            )

            print(
                f"      {index}. {plugin_name}"
            )

        # ----------------------------------------------------
        # Observability
        # ----------------------------------------------------

        print("\n[2] Building observability...")

        audit, monitor = build_observability()

        print(
            f"    Audit : {audit.__class__.__name__}"
        )

        print(
            f"    Monitor: {monitor.__class__.__name__}"
        )

        # ----------------------------------------------------
        # Pipeline object
        # ----------------------------------------------------

        pipeline = {
            "plugins": plugins,
            "audit": audit,
            "monitor": monitor,
        }

        # ----------------------------------------------------
        # Run assignment suite
        # ----------------------------------------------------

        print("\n[3] Running assignment suite...")

        result = await run_assignment_suite(
            pipeline
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        if result is not None:

            print("\n[4] Suite summary")

            print(
                "    Safe queries   : "
                f"{len(result.get('safe_queries', []))}"
            )

            print(
                "    Attack queries : "
                f"{len(result.get('attack_queries', []))}"
            )

            rate_limit = result.get(
                "rate_limit",
                {},
            )

            print(
                "    Rate limit     : "
                f"sent={rate_limit.get('sent', 0)}, "
                f"passed={rate_limit.get('passed', 0)}, "
                f"blocked={rate_limit.get('blocked', 0)}"
            )

            print(
                "    Edge cases     : "
                f"{len(result.get('edge_cases', []))}"
            )

        # ----------------------------------------------------
        # Check generated files
        # ----------------------------------------------------

        outputs_dir = _REPO_DIR / "outputs"

        expected_files = [
            outputs_dir / "results.json",
            outputs_dir / "audit_log.json",
            outputs_dir / "metrics.json",
        ]

        print("\n[5] Generated artifacts")

        for path in expected_files:

            if path.exists():

                size = path.stat().st_size

                print(
                    f"    [OK] {path} "
                    f"({size} bytes)"
                )

            else:

                print(
                    f"    [MISSING] {path}"
                )

        print(
            "\nCheckpoint 3 completed."
        )

        return result

    except NotImplementedError as exc:

        print(
            "\nChưa hoàn thành Checkpoint 3."
        )

        print(
            "Hãy hoàn thiện:"
        )

        print(
            "    src/assignment/pipeline.py"
        )

        print(
            "\nSau đó chạy lại:"
        )

        print(
            "    python src/main.py --part 3"
        )

        print(
            f"\nDetail: {exc}"
        )

        return None

    except Exception as exc:

        print(
            "\n[ERROR] Checkpoint 3 failed."
        )

        print(
            f"Type   : {type(exc).__name__}"
        )

        print(
            f"Detail : {exc}"
        )

        raise


# ============================================================
# CHECKPOINT 4
# ============================================================

async def part4_attacks():
    """
    Checkpoint 4:
        Red Team
        Red Advance
    """

    print("\n" + "=" * 60)
    print("CHECKPOINT 4: Red + Red Advance")
    print("=" * 60)

    from agents.agent import (
        create_red_agent_default,
        test_agent,
    )

    from agents.guards_agent import (
        create_red_agent_advance,
    )

    from attacks.attacks import (
        run_attacks,
        save_attack_results,
    )

    # --------------------------------------------------------
    # Red Default
    # --------------------------------------------------------

    print("\n--- Create Red Default ---")

    red_default, red_default_runner = (
        create_red_agent_default()
    )

    await test_agent(
        red_default,
        red_default_runner,
    )

    # --------------------------------------------------------
    # Attacks on Red Default
    # --------------------------------------------------------

    print("\n--- Attacks on Red ---")

    unsafe_results = await run_attacks(
        red_default,
        red_default_runner,
        target_name="red_default",
    )

    # --------------------------------------------------------
    # Red Advance
    # --------------------------------------------------------

    print(
        "\n--- Attacks on Red Advance "
        "(bonus B2 tối đa +10 nếu LEAKED) ---"
    )

    red_advance, red_advance_runner = (
        create_red_agent_advance()
    )

    guards_results = await run_attacks(
        red_advance,
        red_advance_runner,
        target_name="red_advance",
    )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    save_attack_results(
        unsafe_results=unsafe_results,
        guards_results=guards_results,
        ai_attacks=None,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    red_leaks = sum(
        1
        for result in unsafe_results
        if result.get("leaked")
    )

    bonus_leaks = sum(
        1
        for result in guards_results
        if result.get("leaked")
    )

    print("\n" + "=" * 60)

    print(
        "Red leaks (B1 tối đa +5): "
        f"{red_leaks}"
    )

    print(
        "Red Advance leaks "
        f"(B2 tối đa +10): {bonus_leaks}"
    )

    print(
        "→ Chọn MỘT bonus (B1 hoặc B2); "
        "grader replay"
    )

    # --------------------------------------------------------
    # Model information
    # --------------------------------------------------------

    from core.config import (
        is_harder_model,
        provider_label,
    )

    if is_harder_model():

        print(
            "\nĐang dùng model khó "
            f"({provider_label()}) — "
            "tuỳ chọn khi săn bonus."
        )

    print("=" * 60)

    return {
        "red_default": unsafe_results,
        "red_advance": guards_results,
        "unsafe": unsafe_results,
        "guards": guards_results,
    }


# ============================================================
# MAIN
# ============================================================

async def main(parts=None):
    """
    Main async entry point.

    Nếu không truyền --part:
        chạy CP2 → CP3 → CP4
    """

    # --------------------------------------------------------
    # API configuration
    # --------------------------------------------------------

    setup_api_key()

    # --------------------------------------------------------
    # Default:
    # CP2 → CP3 → CP4
    # --------------------------------------------------------

    if parts is None:
        parts = [2, 3, 4]

    print(
        "\nLab 11 — Guardrails / HITL / "
        "Responsible AI"
    )

    print(
        f"Repository: {_REPO_DIR}"
    )

    print(
        f"Running parts: {parts}"
    )

    # --------------------------------------------------------
    # Run selected checkpoints
    # --------------------------------------------------------

    for part in parts:

        if part == 2:

            await part2_guardrails()

        elif part == 3:

            await part3_assignment_suite()

        elif part == 4:

            await part4_attacks()

        else:

            print(
                f"Unknown part: {part}. "
                "Dùng --part 2, 3, hoặc 4."
            )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("Lab 11 complete!")
    print("=" * 60)

    print(
        "\nKiểm tra các artifact trong:"
    )

    print(
        f"    {_REPO_DIR / 'outputs'}"
    )


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Lab 11: Guardrails / HITL / "
            "Red Team — "
            "--part khớp Checkpoint "
            "(2, 3, 4)"
        )
    )

    parser.add_argument(
        "--part",
        type=int,
        choices=[2, 3, 4],
        help=(
            "2=CP2 guardrails · "
            "3=CP3 suite · "
            "4=CP4 red-team"
        ),
    )

    args = parser.parse_args()

    if args.part is not None:

        asyncio.run(
            main(parts=[args.part])
        )

    else:

        asyncio.run(main())

