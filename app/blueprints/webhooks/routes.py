# GhostPortal webhook routes
from flask import request, jsonify, current_app
from app.blueprints.webhooks import webhooks_bp
from app.extensions import limiter, csrf

@webhooks_bp.route("/webhooks/paypal", methods=["POST"])
@csrf.exempt
@limiter.limit("100 per minute")
def paypal_webhook():
    from app.utils.paypal import verify_webhook_signature
    webhook_id = current_app.config.get("PAYPAL_WEBHOOK_ID","")
    valid = verify_webhook_signature(
        transmission_id=request.headers.get("PayPal-Transmission-Id",""),
        timestamp=request.headers.get("PayPal-Transmission-Time",""),
        webhook_id=webhook_id, event_body=request.data,
        cert_url=request.headers.get("PayPal-Cert-Url",""),
        actual_sig=request.headers.get("PayPal-Transmission-Sig",""),
        auth_algo=request.headers.get("PayPal-Auth-Algo",""),
    )
    if not valid:
        return jsonify({"error": "invalid signature"}), 401
    return jsonify({"status": "ok"}), 200
