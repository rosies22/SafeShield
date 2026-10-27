
import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from werkzeug.security import check_password_hash

from database import (
    initialize_database,
    create_incident,
    get_all_incidents,
    update_incident_status,
)

app = Flask(__name__)

# Load the secret key from the environment.
app.secret_key = os.environ.get("SAFESHIELD_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SAFESHIELD_SECRET_KEY is missing. "
        "Configure it before starting SafeShield."
    )

# Secure session-cookie settings.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

initialize_database()

INCIDENT_TYPES = [
    "Kidnapping",
    "Attempted Kidnapping",
    "Armed Attack",
    "Burglary",
    "Farm Theft",
    "Livestock Theft",
    "Suspicious Activity",
    "Other Emergency",
]

INCIDENT_STATUSES = [
    "Unverified",
    "Under Review",
    "Verified",
    "Rejected",
    "Resolved",
]


def admin_required(view):
    """Restrict a route to authenticated administrators."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))

        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def dashboard():
    """Display public-safe incident information and summary figures."""

    all_incidents = get_all_incidents()

    # Exclude sensitive descriptions from the public dashboard.
    public_incidents = [
        {
            "id": incident["id"],
            "type": incident["type"],
            "location": incident["location"],
            "status": incident["status"],
            "created_at": incident["created_at"],
        }
        for incident in all_incidents
    ]

    return render_template(
        "dashboard.html",
        incidents=public_incidents,
        total=len(all_incidents),
        open_count=sum(
            1
            for incident in all_incidents
            if incident["status"] != "Resolved"
        ),
        sos_count=sum(
            1
            for incident in all_incidents
            if incident["type"] == "Emergency SOS"
        ),
    )


@app.route("/report", methods=["GET", "POST"])
def report_incident():
    """Allow community members to submit incident reports."""

    if request.method == "POST":
        incident_type = request.form.get(
            "incident_type", ""
        ).strip()
        location = request.form.get("location", "").strip()
        description = request.form.get("description", "").strip()

        if incident_type not in INCIDENT_TYPES:
            flash("Please select a valid incident type.", "error")
            return redirect(url_for("report_incident"))

        if not location or not description:
            flash(
                "Please provide the location and incident details.",
                "error",
            )
            return redirect(url_for("report_incident"))

        create_incident(
            incident_type=incident_type,
            location=location,
            description=description,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        )

        flash(
            "Your incident report has been submitted.",
            "success",
        )
        return redirect(url_for("dashboard"))

    return render_template(
        "report_incident.html",
        incident_types=INCIDENT_TYPES,
    )


@app.route("/sos", methods=["POST"])
def emergency_sos():
    """Record an SOS event in the local database."""

    location = request.form.get("location", "").strip()

    create_incident(
        incident_type="Emergency SOS",
        location=location or "Location not provided",
        description=(
            "SOS activated in the local development prototype."
        ),
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )

    flash(
        "SOS recorded locally. No emergency notification was sent.",
        "error",
    )

    return redirect(url_for("dashboard"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Authenticate the configured administrator."""

    if session.get("is_admin"):
        return redirect(url_for("admin_reports"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        expected_username = os.environ.get(
            "SAFESHIELD_ADMIN_USERNAME", ""
        )
        password_hash = os.environ.get(
            "SAFESHIELD_ADMIN_PASSWORD_HASH", ""
        )

        if (
            expected_username
            and password_hash
            and username == expected_username
            and check_password_hash(password_hash, password)
        ):
            session.clear()
            session["is_admin"] = True

            return redirect(url_for("admin_reports"))

        flash(
            "Invalid administrator credentials.",
            "error",
        )

    return render_template("admin_login.html")


@app.route("/admin/reports")
@admin_required
def admin_reports():
    """Show administrators the full incident reports."""

    incidents = get_all_incidents()

    return render_template(
        "admin_reports.html",
        incidents=incidents,
        incident_statuses=INCIDENT_STATUSES,
    )


@app.route(
    "/admin/reports/<int:incident_id>/status",
    methods=["POST"],
)
@admin_required
def update_status(incident_id):
    """Update an incident's status."""

    new_status = request.form.get("status", "").strip()

    if new_status not in INCIDENT_STATUSES:
        flash(
            "Please select a valid incident status.",
            "error",
        )
        return redirect(url_for("admin_reports"))

    updated = update_incident_status(
        incident_id,
        new_status,
    )

    if not updated:
        flash(
            "Incident not found or its status could not be updated.",
            "error",
        )
    else:
        flash(
            "Incident status updated successfully.",
            "success",
        )

    return redirect(url_for("admin_reports"))


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    """Log out the administrator."""

    session.clear()
    return redirect(url_for("admin_login"))


if __name__ == "__main__":
    app.run(debug=True)
