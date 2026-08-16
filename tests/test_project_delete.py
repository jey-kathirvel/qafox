from pathlib import Path
from unittest import TestCase


class ProjectDeleteSurfaceTests(TestCase):
    def test_list_and_detail_expose_owner_scoped_delete(self):
        source = Path("app/projects.py").read_text(encoding="utf-8")
        self.assertIn("/projects/{esc(project[\"public_id\"])}/delete", source)
        self.assertIn('@router.post("/projects/{public_id}/delete")', source)
        self.assertIn("SET deleted_at = :deleted_at", source)
        self.assertIn("AND owner_user_id = :owner_user_id", source)
        self.assertIn("remove_owned_project_files", source)
        self.assertIn("csrf_valid(request, csrf)", source)

    def test_delete_does_not_run_uploaded_source(self):
        source = Path("app/projects.py").read_text(encoding="utf-8")
        self.assertIn("shutil.rmtree(project_directory, ignore_errors=True)", source)
        self.assertNotIn("subprocess", source)
