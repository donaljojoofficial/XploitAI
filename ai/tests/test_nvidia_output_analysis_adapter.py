from django.test import SimpleTestCase

from ai.llm.nvidia_output_analysis_adapter import NvidiaOutputAnalysisAdapter


class NvidiaOutputAnalysisAdapterTests(SimpleTestCase):
    def setUp(self):
        self.adapter = NvidiaOutputAnalysisAdapter()

    def test_lenient_json_parser_ignores_trailing_text(self):
        payload = '{"findings":{"scan_completed":true}} extra explanation'

        parsed = self.adapter._loads_json_lenient(payload)

        self.assertEqual(parsed, {"findings": {"scan_completed": True}})

    def test_lenient_json_parser_escapes_multiline_string_values(self):
        payload = '{"summary":"line one\nline two","findings":{}}'

        parsed = self.adapter._loads_json_lenient(payload)

        self.assertEqual(parsed["summary"], "line one\nline two")
        self.assertEqual(parsed["findings"], {})
