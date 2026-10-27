
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
)

app = Flask(__name__)

# Configure these environment variables before starting the application.
app.secret_key = os.environ.get("SAFESHIELD_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SAFESHIELD_SECRET_KEY is missing. Configure it before starting SafeShield."
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
    # Public users see summary figures, not incident details.
    all_incidents = get_all_incidents()

    return render_template(
        "dashboard.html",
        incidents=[],
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
    if request.method == "POST":
        incident_type = request.form.get("incident_type", "").strip()
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

        flash("Your incident report has been submitted.", "success")
        return redirect(url_for("dashboard"))

    return render_template(
        "report_incident.html",
        incident_types=INCIDENT_TYPES,
    )


@app.route("/sos", methods=["POST"])
def emergency_sos():
    location = request.form.get("location", "").strip()

    create_incident(
        incident_type="Emergency SOS",
        location=location or "Location not provided",
        description="SOS activated in the local development prototype.",
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )

    flash(
        "SOS recorded locally. No emergency notification was sent.",
        "error",
    )

    return redirect(url_for("dashboard"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
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

        flash("Invalid administrator credentials.", "error")

    return render_template("admin_login.html")


@app.route("/admin/reports")
@admin_required
def admin_reports():
    incidents = get_all_incidents()

    return render_template(
        "admin_reports.html",
        incidents=incidents,
    )


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


if __name__ == "__main__":
    app.run(debug=True)
