import subprocess
import tempfile
import uuid
from pathlib import Path
from unittest import TestCase, mock

from app.project_ingestion import (
    IngestionRejected,
    _run_git,
    cleanup_job_workspace,
    create_job_workspace,
    ingest_git_repository,
    validate_branch,
    validate_repository_url,
)


PUBLIC_DNS = [(None, None, None, None, ("93.184.216.34", 443))]


class RepositoryValidationTests(TestCase):
    def test_accepts_public_https_without_credentials(self):
        with mock.patch("socket.getaddrinfo", return_value=PUBLIC_DNS):
            self.assertEqual(
                validate_repository_url("https://github.com/acme/api.git"),
                "https://github.com/acme/api.git",
            )

    def test_rejects_local_protocol_credentials_and_private_dns(self):
        with self.assertRaises(IngestionRejected):
            validate_repository_url("file:///srv/private/repository")
        with self.assertRaises(IngestionRejected):
            validate_repository_url("https://token@github.com/acme/api.git")
        private_dns = [(None, None, None, None, ("127.0.0.1", 443))]
        with mock.patch("socket.getaddrinfo", return_value=private_dns):
            with self.assertRaises(IngestionRejected):
                validate_repository_url("https://internal.example/repo.git")

    def test_rejects_option_like_and_malformed_branches(self):
        for branch in ("--upload-pack=bad", "../main", "main@{1}", "feature//bad"):
            with self.subTest(branch=branch), self.assertRaises(IngestionRejected):
                validate_branch(branch)


class GitExecutionTests(TestCase):
    def test_git_runner_never_uses_shell_or_inherited_git_configuration(self):
        completed = subprocess.CompletedProcess([], 0, "ok\n", "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch("subprocess.run", return_value=completed) as run:
                self.assertEqual(
                    _run_git("git", ["status"], cwd=root, home=root, timeout=10),
                    "ok",
                )
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["env"]["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(kwargs["env"]["GIT_ALLOW_PROTOCOL"], "https")

    def test_ingestion_uses_bare_fetch_and_archive_without_checkout(self):
        sha = "a" * 40
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory) / "staging"

            def fake_git(_git, arguments, **_kwargs):
                calls.append(arguments)
                if "init" in arguments:
                    (staging / "repository.git").mkdir()
                if "rev-parse" in arguments:
                    return sha
                output = next(
                    (item.removeprefix("--output=") for item in arguments if item.startswith("--output=")),
                    None,
                )
                if output:
                    Path(output).write_bytes(b"safe archive")
                return ""

            with (
                mock.patch("socket.getaddrinfo", return_value=PUBLIC_DNS),
                mock.patch("shutil.which", return_value="git"),
                mock.patch("app.project_ingestion._run_git", side_effect=fake_git),
            ):
                result = ingest_git_repository(
                    "https://github.com/acme/api.git", "main", staging
                )
        flattened = " ".join(item for call in calls for item in call)
        self.assertIn("init --bare", flattened)
        self.assertIn("fetch --depth=1 --no-tags", flattened)
        self.assertIn("archive --format=tar", flattened)
        self.assertNotIn("checkout", flattened)
        self.assertEqual(result.commit_sha, sha)


class JobWorkspaceTests(TestCase):
    def test_workspace_has_bounded_layout_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "jobs"
            public_id = str(uuid.uuid4())
            workspace = create_job_workspace(root, public_id)
            self.assertEqual(
                {item.name for item in workspace.iterdir()},
                {"source", "artifacts", "results", "logs"},
            )
            self.assertTrue(cleanup_job_workspace(root, public_id))
            self.assertFalse(workspace.exists())

    def test_invalid_workspace_identifier_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(cleanup_job_workspace(Path(directory), "../../outside"))
