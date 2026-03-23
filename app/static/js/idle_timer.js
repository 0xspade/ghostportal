// Idle timeout is enforced server-side via session_guard.py.
// The backend redirects to /login after IDLE_TIMEOUT_SECONDS of inactivity.
// No client-side timer needed.
