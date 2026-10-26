from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime

from database import initialize_database, create_incident, get_all_incidents

app = Flask(__name__)
app.secret_key = "dev-key-change-before-deployment"

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


@app.route("/")
def dashboard():
    incidents = get_all_incidents()

    return render_template(
        "dashboard.html",
        incidents=incidents,
        total=len(incidents),
        open_count=sum(
            1 for incident in incidents
            if incident["status"] != "Resolved"
        ),
        sos_count=sum(
            1 for incident in incidents
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
            flash("Please provide the location and incident details.", "error")
            return redirect(url_for("report_incident"))

        create_incident(
            incident_type=incident_type,
            location=location,
            description=description,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        )

        flash("Test incident saved successfully to the database.", "success")
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
        "Test SOS saved to the database. No emergency notification was sent.",
        "error",
    )

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
