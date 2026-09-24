"""Unit tests for the env-var tool filter (_ToolFilter)."""

from garmin_mcp import LOCAL_FILE_TOOLS, _ToolFilter, is_read_only_tool


class FakeApp:
    """Minimal stand-in for FastMCP: records which tools get registered."""

    def __init__(self):
        self.registered = []

    def tool(self, *args, **kwargs):
        explicit = kwargs.get("name") or (
            args[0] if args and isinstance(args[0], str) else None
        )

        def decorator(fn):
            self.registered.append(explicit or fn.__name__)
            return fn

        return decorator

    def run(self):
        return "ran"


def _register(filt, names):
    """Register one no-op tool per name through the filter."""
    for n in names:
        def fn():
            return None

        fn.__name__ = n
        filt.tool()(fn)


def test_no_filter_registers_all():
    app = FakeApp()
    filt = _ToolFilter(app, set(), set())
    _register(filt, ["get_a", "get_b"])
    assert app.registered == ["get_a", "get_b"]


def test_allowlist_only_registers_listed():
    app = FakeApp()
    filt = _ToolFilter(app, {"get_a"}, set())
    _register(filt, ["get_a", "get_b"])
    assert app.registered == ["get_a"]


def test_denylist_skips_listed():
    app = FakeApp()
    filt = _ToolFilter(app, set(), {"get_b"})
    _register(filt, ["get_a", "get_b"])
    assert app.registered == ["get_a"]


def test_allowlist_takes_precedence_over_denylist():
    app = FakeApp()
    filt = _ToolFilter(app, {"get_a"}, {"get_a"})
    _register(filt, ["get_a", "get_b"])
    assert app.registered == ["get_a"]


def test_matching_is_case_insensitive():
    app = FakeApp()
    filt = _ToolFilter(app, {"get_a"}, set())
    _register(filt, ["GET_A"])
    assert app.registered == ["GET_A"]


def test_unknown_filter_names_flags_typos():
    app = FakeApp()
    filt = _ToolFilter(app, {"get_a", "get_typo"}, set())
    _register(filt, ["get_a"])
    assert filt.unknown_filter_names() == ["get_typo"]


def test_explicit_name_kwarg_used_for_matching():
    app = FakeApp()
    filt = _ToolFilter(app, {"real_name"}, set())

    def fn():
        return None

    fn.__name__ = "internal_fn"
    filt.tool(name="real_name")(fn)
    assert app.registered == ["real_name"]
    assert filt.unknown_filter_names() == []


def test_passthrough_to_wrapped_app():
    app = FakeApp()
    filt = _ToolFilter(app, set(), set())
    assert filt.run() == "ran"


def test_blocked_tools_win_over_allowlist():
    app = FakeApp()
    filt = _ToolFilter(app, {"get_a", "download_activity_file"}, set(), blocked=LOCAL_FILE_TOOLS)
    _register(filt, ["get_a", "download_activity_file", "upload_course"])
    assert app.registered == ["get_a"]
    # Blocked tools exist, so they must not be reported as filter typos.
    assert filt.unknown_filter_names() == []


def test_read_only_mode_keeps_only_readers():
    app = FakeApp()
    filt = _ToolFilter(app, set(), set(), read_only=True)
    _register(filt, [
        "get_activities", "count_activities", "download_workout",
        "delete_workouts", "upload_workout", "set_activity_name",
        "log_food", "request_reload", "upsert_and_log",
    ])
    assert app.registered == ["get_activities", "count_activities", "download_workout"]


def test_read_only_classification():
    assert is_read_only_tool("GET_SLEEP_DATA")
    assert not is_read_only_tool("schedule_week")
    assert not is_read_only_tool("remove_gear_from_activity")
