import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class ExtensionSignoffTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所")
        self.coord=self.db.add_user("协调员甲","coordinator","响应中心")
        self.coord2=self.db.add_user("协调员乙","coordinator","响应中心")
        self.maint=self.db.add_user("维护者甲","maintainer","项目组")
        self.maint2=self.db.add_user("维护者乙","maintainer","项目组")
        self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_member(self.report,self.maint2,"maintainer",self.coord)
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _request(self):
        return self.db.request_extension(self.report,"2026-12-15","上游依赖尚未修复",self.coord)
    def _all_approve(self,req):
        self.db.vote_extension(req,self.reporter,"approve","同意延期")
        self.db.vote_extension(req,self.maint,"approve")
        self.db.vote_extension(req,self.maint2,"approve")
    def _info(self):
        return self.db.get_report_for_user(self.report,self.coord)["extension_requests"][0]

    def test_full_signoff_then_other_coordinator_review(self):
        req=self._request()
        self._all_approve(req)
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("2026-10-30",report["confidential_until"])
        self.assertEqual("review",self._info()["status"])
        self.db.review_extension(req,self.coord2,"approve","流程合规")
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("2026-12-15",report["confidential_until"])
        self.assertEqual("2026-12-15",report["extensions"][-1]["new_deadline"])
        info=self._info()
        self.assertEqual("approved",info["status"])
        self.assertEqual("协调员乙",info["reviewer_name"])
        self.assertEqual({"approve"},{v["decision"] for v in info["votes"]})
        self.assertTrue(self.db.notifications_for(self.reporter))
        self.assertTrue(self.db.notifications_for(self.maint))

    def test_any_rejection_closes_request_and_keeps_deadline(self):
        req=self._request()
        self.db.vote_extension(req,self.reporter,"approve")
        self.db.vote_extension(req,self.maint,"reject","风险已缓解，不应延期")
        self.assertEqual("rejected",self._info()["status"])
        report=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("2026-10-30",report["confidential_until"])
        self.assertEqual([],report["extensions"])
        with self.assertRaisesRegex(DomainError,"不接受会签"):
            self.db.vote_extension(req,self.maint2,"approve")

    def test_initiator_self_review_rejected(self):
        req=self._request()
        self._all_approve(req)
        with self.assertRaisesRegex(DomainError,"不能复核自己"):
            self.db.review_extension(req,self.coord,"approve")
        self.assertEqual("review",self._info()["status"])
        self.db.review_extension(req,self.coord2,"reject","理由不充分")
        self.assertEqual("rejected",self._info()["status"])
        self.assertEqual("2026-10-30",self.db.get_report_for_user(self.report,self.coord)["confidential_until"])

    def test_content_change_invalidates_signoff(self):
        req=self._request()
        self.db.vote_extension(req,self.reporter,"approve")
        self.db.set_fix_plan(self.report,self.maint,"改为等待上游补丁","2026-11-01")
        self.assertEqual("invalidated",self._info()["status"])
        with self.assertRaisesRegex(DomainError,"不接受会签"):
            self.db.vote_extension(req,self.maint,"approve")
        self._request()
        self.db.update_summary(self.report,"更新后的摘要：影响面扩大",self.reporter)
        self.assertEqual("invalidated",self._info()["status"])
        req3=self._request()
        self._all_approve(req3)
        self.db.set_affected_versions(self.report,["3.2.0","3.2.1"],self.coord)
        self.assertEqual("invalidated",self._info()["status"])
        with self.assertRaisesRegex(DomainError,"不在复核阶段"):
            self.db.review_extension(req3,self.coord2,"approve")

    def test_page_payload_shows_votes_pending_and_deadlines(self):
        req=self._request()
        self.db.vote_extension(req,self.reporter,"approve","没意见")
        info=self.db.get_report_for_user(self.report,self.maint)["extension_requests"][0]
        self.assertEqual("2026-10-30",info["old_deadline"])
        self.assertEqual("2026-12-15",info["new_deadline"])
        self.assertEqual(["报告人"],[v["user_name"] for v in info["votes"]])
        self.assertEqual({"维护者甲","维护者乙"},{p["name"] for p in info["pending"]})
        self.assertIn("维护者",info["waiting_on"])
        self.db.vote_extension(req,self.maint,"approve")
        self.db.vote_extension(req,self.maint2,"approve")
        info=self._info()
        self.assertEqual("review",info["status"])
        self.assertIn("复核",info["waiting_on"])

    def test_single_active_request_and_voter_rules(self):
        req=self._request()
        with self.assertRaisesRegex(DomainError,"进行中"):
            self._request()
        with self.assertRaisesRegex(DomainError,"只有报告人和"):
            self.db.vote_extension(req,self.coord,"approve")
        with self.assertRaisesRegex(DomainError,"只有报告人和"):
            self.db.vote_extension(req,self.outsider,"approve")
        self.db.vote_extension(req,self.reporter,"approve")
        with self.assertRaisesRegex(DomainError,"已提交"):
            self.db.vote_extension(req,self.reporter,"reject")

    def test_request_and_review_validation(self):
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.request_extension(self.report,"2026-12-15","合理的延期理由",self.maint)
        with self.assertRaisesRegex(DomainError,"晚于"):
            self.db.request_extension(self.report,"2026-10-01","合理的延期理由",self.coord)
        with self.assertRaisesRegex(DomainError,"至少5个字符"):
            self.db.request_extension(self.report,"2026-12-15","短",self.coord)
        req=self._request()
        with self.assertRaisesRegex(DomainError,"不在复核阶段"):
            self.db.review_extension(req,self.coord2,"approve")
        self._all_approve(req)
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.review_extension(req,self.maint,"approve")

if __name__=="__main__": unittest.main()
