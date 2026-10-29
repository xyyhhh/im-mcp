"""Announcement regressions with fictional, synthetic message payloads."""

import unittest

from wechat_mcp.parser import build_content, type_label


class TestAnnouncements(unittest.TestCase):
    def test_new_notice_without_title_and_with_sender_prefix(self):
        body = "练习通知\n请于5月8日之前提交测试文档。"
        raw = (
            'wxid_fixture_sender:\n<?xml version="1.0"?><msg><appmsg>'
            '<type>87</type><textannouncement><![CDATA[' + body +
            ']]></textannouncement></appmsg></msg>'
        )
        self.assertEqual(build_content((87 << 32) | 49, raw.encode(), None), "[群公告] " + body)
        self.assertEqual(type_label((87 << 32) | 49), "群公告")

    def test_plain_text_field_has_priority_over_nested_data(self):
        raw = (
            '<appmsg><textannouncement>可读正文 &amp; 说明</textannouncement>'
            '<announcement><![CDATA[<group_notice_item><datalist>'
            '<dataitem datatype="1"><datadesc>备用正文</datadesc></dataitem>'
            '</datalist></group_notice_item>]]></announcement></appmsg>'
        )
        self.assertEqual(build_content((87 << 32) | 49, raw, None), "[群公告] 可读正文 & 说明")

    def test_compressed_announcement(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest("optional zstandard dependency unavailable")
        raw = '<appmsg><textannouncement>合成通知正文</textannouncement></appmsg>'
        compressed = zstandard.ZstdCompressor().compress(raw.encode("utf-8"))
        self.assertEqual(build_content((87 << 32) | 49, compressed, None), "[群公告] 合成通知正文")

    def test_nested_text_items_exclude_attachment_metadata(self):
        raw = (
            '<appmsg><announcement><![CDATA[<group_notice_item><datalist>'
            '<dataitem datatype="8"><datadesc>attachment-only</datadesc>'
            '<cdn_datakey>synthetic-not-for-display</cdn_datakey></dataitem>'
            '<dataitem datatype="1"><datadesc>第一段</datadesc></dataitem>'
            '<dataitem datatype="1"><datadesc>第二段</datadesc></dataitem>'
            '</datalist></group_notice_item>]]></announcement></appmsg>'
        )
        # Ordinary escaped nested XML is sufficient; no network or attachments
        # are needed to read the announcement text.
        result = build_content((87 << 32) | 49, raw, None)
        self.assertEqual(result, "[群公告] 第一段\n第二段")
        self.assertNotIn("synthetic-not-for-display", result)

    def test_legacy_notice_and_source_fallback(self):
        raw = '<appmsg><textannouncement>旧格式通知</textannouncement></appmsg>'
        self.assertEqual(build_content((25 << 32) | 49, None, raw), "[群公告] 旧格式通知")

    def test_notice_without_body_keeps_title_or_type(self):
        message_type = (87 << 32) | 49
        self.assertEqual(build_content(message_type, '<appmsg><title>摘要</title></appmsg>', None), "[群公告] 摘要")
        self.assertEqual(build_content(message_type, '<appmsg><type>87</type></appmsg>', None), "[群公告]")

    def test_other_app_messages_are_unchanged(self):
        self.assertEqual(build_content((6 << 32) | 49, '<appmsg><title>fixture.txt</title></appmsg>', None), "[文件] fixture.txt")
        self.assertEqual(build_content((999 << 32) | 49, '<appmsg/>', None), "[消息]")


if __name__ == "__main__":
    unittest.main()
