"""Load tests for goop-shield API.

Run with:
    locust -f tests/load/locustfile.py --headless -u 50 -r 10 --run-time 60s
"""

from locust import HttpUser, between, task


class ShieldUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(10)
    def defend(self):
        self.client.post(
            "/api/v1/defend",
            json={
                "prompt": "What is the capital of France?",
                "context": {},
            },
        )

    @task(5)
    def scan_response(self):
        self.client.post(
            "/api/v1/scan-response",
            json={
                "response_text": "The capital of France is Paris.",
                "original_prompt": "What is the capital of France?",
            },
        )

    @task(3)
    def health(self):
        self.client.get("/api/v1/health")

    @task(1)
    def metrics(self):
        self.client.get("/api/v1/metrics")
