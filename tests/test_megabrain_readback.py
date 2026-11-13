"""MegaBrain readback QA: contradictory metadata gets surfaced without exposing content."""
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERIFY=ROOT/"bin/mitr3-rag-mcp-verify.py"
module=None
if VERIFY.is_file():
 spec=importlib.util.spec_from_file_location("readback",VERIFY)
 module=importlib.util.module_from_spec(spec)
 spec.loader.exec_module(module)

@unittest.skipUnless(VERIFY.is_file(), "bin/mitr3-rag-mcp-verify.py is not in this checkout; remote readback QA skipped")
class RedactionQaTests(unittest.TestCase):
 def test_placeholder_false_flag_is_inconsistency(self):
  obj={"found":True,"index_status":"ready","indexed_chunks":0,
       "content_redacted":False,"safe_content":"[REDACTED:SECRET_CONTENT]"}
  item=module.classify_readback(obj,"https://ctftime.org/writeup/123","x")
  self.assertEqual(item["reason"],"redacted_by_server")
  self.assertTrue(item["redaction_flag_mismatch"])
  self.assertFalse(item["readback_ok"])
  self.assertNotIn("safe_content",item)

 def test_placeholder_true_flag_consistent(self):
  obj={"found":True,"content_redacted":True,"safe_content":"[REDACTED:SECRET_CONTENT]"}
  item=module.classify_readback(obj,"https://ctftime.org/writeup/123","x")
  self.assertFalse(item["redaction_flag_mismatch"])
  self.assertTrue(item["safe_content_placeholder"])

 def test_accessible_source_checks_both_id_and_url(self):
  obj={"found":True,"content_redacted":False,
       "safe_content":"case x with source https://ctftime.org/writeup/123"}
  item=module.classify_readback(obj,"https://ctftime.org/writeup/123","x")
  self.assertTrue(item["readback_ok"])
  missing=module.classify_readback(obj,"https://ctftime.org/writeup/999","x")
  self.assertEqual(missing["reason"],"missing_metadata_or_body")

 def test_tool_error_does_not_mark_readable(self):
  obj={"found":True,"safe_content":"case x https://ctftime.org/writeup/123"}
  item=module.classify_readback(obj,"https://ctftime.org/writeup/123","x",tool_error=True)
  self.assertFalse(item["readback_ok"])

 def test_literal_word_redacted_in_normal_text_not_placeholder(self):
  obj={"found":True,"content_redacted":False,
    "safe_content":"case x https://ctftime.org/writeup/123 REDACTED is a sample term"}
  item=module.classify_readback(obj,"https://ctftime.org/writeup/123","x")
  self.assertTrue(item["readback_ok"])
  self.assertFalse(item["safe_content_placeholder"])

if __name__=="__main__":unittest.main()

