import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_resolved(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])

class ExtensionCosignTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员甲","coordinator","响应中心"); self.coord2=self.db.add_user("协调员乙","coordinator","响应中心")
        self.maint=self.db.add_user("维护者甲","maintainer","项目组"); self.maint2=self.db.add_user("维护者乙","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord); self.db.add_member(self.report,self.maint2,"maintainer",self.coord)
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _propose(self):
        return self.db.propose_extension(self.report,"2026-12-15","上游依赖尚未发布修复版本",self.coord)
    def test_full_cosign_flow(self):
        rid=self._propose()
        detail=self.db.extension_request_detail(rid)
        self.assertEqual("voting",detail["status"]); self.assertEqual("2026-10-30",detail["old_deadline"]); self.assertEqual("2026-12-15",detail["new_deadline"])
        self.assertEqual({"报告人","维护者甲","维护者乙"},{v["name"] for v in detail["pending_voters"]})
        self.assertTrue(self.db.notifications_for(self.reporter))
        self.db.vote_extension(rid,self.reporter,True,"同意延期")
        self.db.vote_extension(rid,self.maint,True,"修复需要更多时间")
        detail=self.db.extension_request_detail(rid)
        self.assertEqual(["维护者乙"],[v["name"] for v in detail["pending_voters"]]); self.assertIn("维护者乙",detail["pending_on"])
        self.db.vote_extension(rid,self.maint2,True,"")
        detail=self.db.extension_request_detail(rid)
        self.assertEqual("review",detail["status"]); self.assertIn("协调员乙",detail["pending_on"]); self.assertNotIn("协调员甲",detail["pending_on"])
        with self.assertRaisesRegex(DomainError,"不能复核自己的"):
            self.db.review_extension(rid,self.coord,True)
        self.db.review_extension(rid,self.coord2,True)
        detail=self.db.extension_request_detail(rid)
        self.assertEqual("approved",detail["status"]); self.assertEqual("",detail["pending_on"])
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("2026-12-15",report["confidential_until"]); self.assertEqual("2026-12-15",report["extensions"][-1]["new_deadline"])
        votes={v["user_id"]:v for v in detail["votes"]}
        self.assertEqual("同意延期",votes[self.reporter]["comment"]); self.assertEqual(1,votes[self.maint]["approve"])
    def test_rejection_keeps_original_deadline(self):
        rid=self._propose()
        self.db.vote_extension(rid,self.reporter,True,"")
        self.db.vote_extension(rid,self.maint,False,"补丁已就绪，无需延期")
        detail=self.db.extension_request_detail(rid)
        self.assertEqual("rejected",detail["status"])
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("2026-10-30",report["confidential_until"]); self.assertEqual([],report["extensions"])
        with self.assertRaisesRegex(DomainError,"表决阶段"):
            self.db.vote_extension(rid,self.maint2,True,"")
        with self.assertRaisesRegex(DomainError,"复核阶段"):
            self.db.review_extension(rid,self.coord2,True)
    def test_content_change_invalidates_request(self):
        rid=self._propose()
        self.db.vote_extension(rid,self.reporter,True,"")
        self.db.update_report_details(self.report,self.reporter,summary="更新摘要：影响鉴权与会话固定")
        self.assertEqual("invalidated",self.db.extension_request_detail(rid)["status"])
        rid2=self.db.propose_extension(self.report,"2026-12-20","重新评估后的延期申请",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验","2026-11-01")
        self.assertEqual("invalidated",self.db.extension_request_detail(rid2)["status"])
        rid3=self.db.propose_extension(self.report,"2026-12-25","第三次发起延期申请",self.coord)
        self.db.update_report_details(self.report,self.coord,versions=["3.2.0","3.2.1"])
        self.assertEqual("invalidated",self.db.extension_request_detail(rid3)["status"])
        rid4=self.db.propose_extension(self.report,"2026-12-28","内容未变时再次申请",self.coord)
        self.db.update_report_details(self.report,self.coord,summary="更新摘要：影响鉴权与会话固定")
        self.assertEqual("voting",self.db.extension_request_detail(rid4)["status"])
    def test_outsider_duplicate_vote_and_propose_validation(self):
        rid=self._propose()
        with self.assertRaisesRegex(DomainError,"报告人和维护者"):
            self.db.vote_extension(rid,self.outsider,True,"")
        self.db.vote_extension(rid,self.reporter,True,"")
        with self.assertRaisesRegex(DomainError,"已表决"):
            self.db.vote_extension(rid,self.reporter,False,"改主意")
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.propose_extension(self.report,"2026-12-15","理由充分足够长",self.maint)
        with self.assertRaisesRegex(DomainError,"晚于当前"):
            self.db.propose_extension(self.report,"2026-10-01","理由充分足够长",self.coord)

if __name__=="__main__": unittest.main()
