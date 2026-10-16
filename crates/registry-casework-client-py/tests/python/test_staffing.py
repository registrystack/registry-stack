"""ReviewTask staffing wire shapes, exact selectors and provider-free flows."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from bootstrap import ensure_built
ensure_built()
from registry_casework_client import CaseworkClient, CaseworkClientError

ID = "00000000-0000-4000-8000-000000000001"
PREVIEW = "00000000-0000-4000-8000-000000000009"
SUBJECT = {"source":"registry", "type":"proposal", "id":"proposal-7", "version":"3", "digest":f"sha256:{'a'*64}"}
TASK = {"taskId":ID,"requestId":PREVIEW,"subject":SUBJECT,"requesterReference":"REF-7","displayReference":"REF-7","createdAt":"2026-10-14T00:00:00Z","deadlineAt":"2026-10-20T00:00:00Z","stageId":"review","stageIndex":0,"queue":"review","revision":3,"eligibleProfiles":["staff"],"state":{"held":{"holder":{"issuer":"https://issuer.example","subject":"staff-1"}}}}

class Handler(BaseHTTPRequestHandler):
    seen = []
    staffing_notice = False
    def log_message(self,*args): pass
    def do_GET(self): self.answer()
    def do_POST(self): self.answer()
    def answer(self):
        raw=self.rfile.read(int(self.headers.get("content-length","0")))
        self.seen.append({"path":self.path,"headers":{k.lower():v for k,v in self.headers.items()},"body":json.loads(raw) if raw else None})
        selected={"taskId":ID,"revision":3}
        clock={**selected,"deadlineAt":TASK["deadlineAt"]}
        if self.staffing_notice and "/review-tasks" in self.path:
            value={"taskId":ID,"requestId":PREVIEW,"queue":"review","revision":3,"state":"open","staffingDiagnostic":"no-cover-available"} if "/supervision" in self.path else {**TASK,"state":"open","staffingDiagnostic":"no-cover-available"}
            value={"items":[value],"status":"complete"}
        elif "/review-tasks/next" in self.path: value=TASK
        elif "/review-tasks/holdings" in self.path: value={"items":[TASK],"status":"complete"}
        elif "caseload" in self.path: value={"previewId":PREVIEW,"directoryRevision":4,"tasks":[selected],"expiresAt":"2026-10-14T01:00:00Z"} if self.path.endswith("preview") else {"moved":[selected]}
        else: value={"previewId":PREVIEW,"directoryRevision":4,"tasks":[clock],"expiresAt":"2026-10-14T01:00:00Z"} if self.path.endswith("preview") else {"tasks":[clock]}
        payload=json.dumps(value).encode();self.send_response(200);self.send_header("content-type","application/json");self.send_header("traceparent","00-0123456789abcdef0123456789abcdef-0123456789abcdef-01");self.end_headers();self.wfile.write(payload)

class StaffingTests(unittest.TestCase):
    def setUp(self):
        Handler.seen=[];Handler.staffing_notice=False;self.server=HTTPServer(("127.0.0.1",0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.client=CaseworkClient(f"http://127.0.0.1:{self.server.server_port}/tenant")
    def tearDown(self): self.server.shutdown();self.thread.join();self.server.server_close()
    def test_next_and_holdings_preserve_exact_selectors(self):
        query={"queue":"review","ownership":"assigned-to-me","subjectSource":SUBJECT["source"],"subjectType":SUBJECT["type"],"subjectId":SUBJECT["id"],"subjectVersion":SUBJECT["version"],"subjectDigest":SUBJECT["digest"],"reference":"REF-7","sort":"reference","limit":25}
        self.assertEqual(self.client.next_review_task("staff-token","staff",query)["value"],TASK)
        self.assertEqual(self.client.review_task_holdings("staff-token","staff",query)["value"]["items"],[TASK])
        for call in Handler.seen:
            parameters=parse_qs(urlsplit(call["path"]).query);self.assertEqual(parameters["subjectDigest"],[SUBJECT["digest"]]);self.assertEqual(parameters["sort"],["reference"]);self.assertEqual(call["headers"]["registry-casework-profile"],"staff");self.assertNotIn("registry-source-profile",call["headers"])
    def test_caseload_and_clock_apply_only_reviewed_preview(self):
        movement={"from":{"issuer":"https://issuer.example","subject":"staff-1"},"to":{"issuer":"https://issuer.example","subject":"staff-2"},"reason":"Cover"}
        preview=self.client.preview_caseload_move("staff-token","staff",movement)["value"]
        self.assertEqual(self.client.apply_caseload_move("staff-token","staff","move-7",{"previewId":preview["previewId"]})["value"]["moved"],[{"taskId":ID,"revision":3}])
        preview=self.client.preview_clock_recompute("staff-token","staff",{"taskIds":[ID]})["value"]
        self.assertEqual(len(self.client.apply_clock_recompute("staff-token","staff","clock-7",{"previewId":preview["previewId"]})["value"]["tasks"]),1)
        self.assertEqual(Handler.seen[1]["body"],{"previewId":PREVIEW});self.assertEqual(Handler.seen[1]["headers"]["idempotency-key"],"move-7");self.assertEqual(Handler.seen[2]["body"],{"taskIds":[ID]});self.assertEqual(Handler.seen[3]["headers"]["idempotency-key"],"clock-7")
    def test_invalid_inputs_fail_before_http(self):
        calls=(lambda:self.client.decide_review_task("staff-token","staff",ID,1,"decision",{"decision":{"type":"answer","outcome":"answered","result":[]}}),lambda:self.client.save_review_task_draft("staff-token","staff",ID,1,"draft",{"body":{"private-canary":"x"*(17*1024)}}),lambda:self.client.next_review_task("staff-token","staff",{"subjectId":"private-canary"}),lambda:self.client.review_task_holdings("staff-token","staff",{"limit":101}),lambda:self.client.preview_clock_recompute("staff-token","staff",{"taskIds":[ID,ID]}),lambda:self.client.apply_caseload_move("staff-token","staff","move",{"previewId":"00000000-0000-0000-0000-000000000000"}))
        for call in calls:
            with self.assertRaises(CaseworkClientError) as raised:call()
            self.assertEqual(raised.exception.kind,"invalid-request");self.assertNotIn("private-canary",str(raised.exception))
        self.assertEqual(Handler.seen,[])
    def test_a_response_cannot_substitute_another_reference(self):
        with self.assertRaises(CaseworkClientError) as raised:self.client.next_review_task("staff-token","staff",{"reference":"another"})
        self.assertEqual(raised.exception.kind,"protocol")

    def test_review_and_supervision_preserve_optional_staffing_notice(self):
        Handler.staffing_notice=True
        blocked={**TASK,"state":"open","staffingDiagnostic":"no-cover-available"}
        row={"taskId":ID,"requestId":PREVIEW,"queue":"review","revision":3,"state":"open","staffingDiagnostic":"no-cover-available"}
        self.assertEqual(self.client.review_tasks("staff-token","staff")["value"]["items"],[blocked])
        self.assertEqual(self.client.supervisory_review_tasks("supervisor-token","supervisor")["value"]["items"],[row])
        Handler.staffing_notice=False
        self.assertNotIn("staffingDiagnostic",self.client.review_task_holdings("staff-token","staff")["value"]["items"][0])
