# HR Source Integration (Workday Connector)

```python
"""
HR Source Integration - Workday to IGA Platform Connector
Polls Workday for employee lifecycle events and triggers provisioning.
"""
import requests
from datetime import datetime, timedelta
import logging

class WorkdayIdentityConnector:
    def __init__(self, config):
        self.base_url = config["workday_api_url"]
        self.tenant = config["tenant"]
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.session = requests.Session()
        self.logger = logging.getLogger("workday_connector")

    def get_access_token(self):
        """Authenticate to Workday REST API."""
        token_url = f"{self.base_url}/ccx/oauth2/{self.tenant}/token"
        response = self.session.post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        })
        response.raise_for_status()
        return response.json()["access_token"]

    def fetch_worker_changes(self, since_datetime):
        """Fetch all worker lifecycle events since the last sync."""
        headers = {"Authorization": f"Bearer {self.get_access_token()}"}
        params = {
            "Updated_From": since_datetime.isoformat(),
            "Updated_Through": datetime.utcnow().isoformat(),
            "Count": 100
        }

        workers = []
        url = f"{self.base_url}/ccx/api/v1/{self.tenant}/workers"

        while url:
            response = self.session.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            workers.extend(data.get("data", []))
            url = data.get("next", None)
            params = {}

        return workers

    def map_lifecycle_event(self, worker):
        """Map Workday worker data to identity lifecycle event."""
        worker_data = worker.get("workerData", {})
        employment = worker_data.get("employmentData", {})
        personal = worker_data.get("personalData", {})

        event = {
            "employee_id": worker.get("id"),
            "first_name": personal.get("legalName", {}).get("firstName"),
            "last_name": personal.get("legalName", {}).get("lastName"),
            "email": worker_data.get("emailAddress"),
            "job_code": employment.get("jobProfile", {}).get("id"),
            "job_title": employment.get("jobProfile", {}).get("name"),
            "department": employment.get("organization", {}).get("name"),
            "department_code": employment.get("organization", {}).get("id"),
            "manager_id": employment.get("managerId"),
            "location": employment.get("location", {}).get("name"),
            "cost_center": employment.get("costCenter", {}).get("id"),
            "hire_date": employment.get("hireDate"),
            "termination_date": employment.get("terminationDate"),
            "status": employment.get("status"),
            "worker_type": employment.get("workerType"),
        }

        # Determine lifecycle transition
        if event["status"] == "Active" and event["hire_date"]:
            hire_date = datetime.fromisoformat(event["hire_date"])
            if hire_date > datetime.utcnow():
                event["lifecycle_event"] = "PRE_HIRE"
            else:
                event["lifecycle_event"] = "JOINER"
        elif event["status"] == "Active":
            event["lifecycle_event"] = "MOVER"  # Department or role change
        elif event["status"] == "Terminated":
            event["lifecycle_event"] = "LEAVER"
        elif event["status"] == "On Leave":
            event["lifecycle_event"] = "LEAVE_OF_ABSENCE"

        return event

    def process_lifecycle_events(self, since_datetime):
        """Main processing loop for identity lifecycle events."""
        workers = self.fetch_worker_changes(since_datetime)
        events = []

        for worker in workers:
            event = self.map_lifecycle_event(worker)
            events.append(event)
            self.logger.info(
                f"Lifecycle event: {event['lifecycle_event']} for "
                f"{event['first_name']} {event['last_name']} "
                f"(EmpID: {event['employee_id']})"
            )

        return events
```
