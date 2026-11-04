import unittest

from investigator.core.context import InvestigationContext
from investigator.core.exceptions import PipelineConfigurationError
from investigator.core.models import Evidence, InvestigationCase, InvestigationStatus, InvestigationTarget, StageResult, StageStatus
from investigator.core.pipeline import InvestigationPipeline
from investigator.core.stage import InvestigationStage


class SuccessfulStage(InvestigationStage):
    def __init__(self, name, dependencies=()):
        self.name = name
        self.dependencies = dependencies

    def execute(self, context):
        context.metadata[self.name] = "executed"
        return StageResult.completed(self.name, evidence=(Evidence("test", "fixture", self.name),))


class FailingStage(InvestigationStage):
    name = "failure"

    def execute(self, context):
        raise RuntimeError("controlled failure")


class WaitingStage(InvestigationStage):
    name = "approval"

    def execute(self, context):
        return StageResult(self.name, StageStatus.WAITING_FOR_INPUT, message="Approval required")


class DisabledStage(SuccessfulStage):
    def enabled(self, context):
        return False


class FrameworkModelTests(unittest.TestCase):
    def test_case_factory_creates_stable_prefix_and_normalizes_target(self):
        case = InvestigationCase.create("  example.com  ", selected_modules=("osint",))
        self.assertTrue(case.case_id.startswith("CASE_"))
        self.assertEqual(case.original_target, "example.com")
        self.assertEqual(case.status, InvestigationStatus.CREATED)

    def test_target_rejects_invalid_confidence(self):
        with self.assertRaises(ValueError):
            InvestigationTarget("example.com", confidence=1.5)

    def test_failed_result_requires_error(self):
        with self.assertRaises(ValueError):
            StageResult("stage", StageStatus.FAILED)


class InvestigationPipelineTests(unittest.TestCase):
    def context(self):
        return InvestigationContext(InvestigationCase.create("example.com"))

    def test_executes_stages_in_order_and_collects_evidence(self):
        context = self.context()
        pipeline = InvestigationPipeline([SuccessfulStage("resolve"), SuccessfulStage("collect", ("resolve",))])
        result = pipeline.run(context)
        self.assertEqual(result.status, InvestigationStatus.COMPLETED)
        self.assertEqual([item.stage_name for item in result.stage_results], ["resolve", "collect"])
        self.assertEqual([item.value for item in context.evidence], ["resolve", "collect"])

    def test_rejects_duplicate_and_out_of_order_dependencies(self):
        with self.assertRaises(PipelineConfigurationError):
            InvestigationPipeline([SuccessfulStage("same"), SuccessfulStage("same")])
        with self.assertRaises(PipelineConfigurationError):
            InvestigationPipeline([SuccessfulStage("collect", ("resolve",))])

    def test_converts_exception_to_failed_result_and_stops(self):
        context = self.context()
        result = InvestigationPipeline([FailingStage(), SuccessfulStage("never")]).run(context)
        self.assertEqual(result.status, InvestigationStatus.FAILED)
        self.assertEqual(len(result.stage_results), 1)
        self.assertEqual(result.stage_results[0].error, "controlled failure")
        self.assertNotIn("never", context.metadata)

    def test_waiting_stage_pauses_pipeline(self):
        result = InvestigationPipeline([WaitingStage(), SuccessfulStage("later")]).run(self.context())
        self.assertEqual(result.status, InvestigationStatus.WAITING_FOR_INPUT)
        self.assertEqual(len(result.stage_results), 1)

    def test_disabled_stage_is_skipped(self):
        result = InvestigationPipeline([DisabledStage("optional")]).run(self.context())
        self.assertEqual(result.status, InvestigationStatus.COMPLETED)
        self.assertEqual(result.stage_results[0].status, StageStatus.SKIPPED)

    def test_progress_callback_receives_start_and_completion(self):
        updates = []
        InvestigationPipeline([SuccessfulStage("resolve")]).run(self.context(), progress_callback=updates.append)
        self.assertEqual([update.status for update in updates], [StageStatus.RUNNING, StageStatus.COMPLETED])


if __name__ == "__main__":
    unittest.main()
