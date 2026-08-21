"""A minimal background job runner for long workflow steps.

Ingesting documents or collecting evidence takes long enough to block a
request, so the UI starts a job and polls it. Jobs live in memory: this is a
single-user local tool, and the authoritative record of what happened is the
artifact the step writes to disk, not the job entry.

A job function reports progress through a ``JobHandle``. It must not return
anything the UI needs beyond a redirect target, because the pages read their
data back from disk.
"""

from __future__ import annotations

import threading
import traceback
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

#: Completed jobs kept for inspection before the oldest are discarded.
MAX_JOBS = 50


class JobStatus(str, Enum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


@dataclass
class JobStep:
    message: str
    at: str


@dataclass
class Job:
    job_id: str
    type: str
    title: str
    status: JobStatus = JobStatus.RUNNING
    started_at: str = ""
    finished_at: str = ""
    steps: list[JobStep] = field(default_factory=list)
    error: str = ""
    detail: str = ""
    redirect: str = "/"
    run_id: str = ""

    @property
    def done(self) -> bool:
        return self.status is not JobStatus.RUNNING

    @property
    def message(self) -> str:
        if self.steps:
            return self.steps[-1].message
        return "Starting"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobHandle:
    """What a running job function may report back."""

    def __init__(self, job: Job, lock: threading.Lock) -> None:
        self._job = job
        self._lock = lock

    def step(self, message: str) -> None:
        with self._lock:
            self._job.steps.append(JobStep(message=message, at=_now()))

    def set_run_id(self, run_id: str) -> None:
        with self._lock:
            self._job.run_id = run_id

    def set_redirect(self, href: str) -> None:
        with self._lock:
            self._job.redirect = href


class JobRegistry:
    """In-memory job store. Thread-safe; one instance per process."""

    def __init__(self) -> None:
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()

    def start(
        self,
        *,
        job_type: str,
        title: str,
        redirect: str,
        work: Callable[[JobHandle], None],
    ) -> Job:
        job_id = f"JOB-{uuid.uuid4().hex[:12]}"
        job = Job(
            job_id=job_id,
            type=job_type,
            title=title,
            started_at=_now(),
            redirect=redirect,
        )
        with self._lock:
            self._jobs[job_id] = job
            self._prune()

        handle = JobHandle(job, self._lock)

        def run() -> None:
            try:
                work(handle)
            except Exception as exc:
                with self._lock:
                    job.status = JobStatus.FAILED
                    job.error = str(exc) or exc.__class__.__name__
                    job.detail = traceback.format_exc(limit=3)
                    job.finished_at = _now()
                    job.steps.append(JobStep(message=f"Failed: {job.error}", at=_now()))
            else:
                with self._lock:
                    job.status = JobStatus.SUCCEEDED
                    job.finished_at = _now()
                    job.steps.append(JobStep(message="Done", at=_now()))

        threading.Thread(target=run, name=job_id, daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def running(self) -> list[Job]:
        with self._lock:
            return [j for j in self._jobs.values() if j.status is JobStatus.RUNNING]

    def _prune(self) -> None:
        while len(self._jobs) > MAX_JOBS:
            for job_id, job in list(self._jobs.items()):
                if job.done:
                    del self._jobs[job_id]
                    break
            else:
                break


registry = JobRegistry()
