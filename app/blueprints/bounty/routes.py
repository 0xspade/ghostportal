# GhostPortal -- Project-Apocalypse -- Bounty Payment Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

from datetime import datetime, timezone
from flask import (abort, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)

from app.blueprints.bounty import bounty_bp
from app.blueprints.decorators import owner_required, parse_uuid
from app.extensions import db
from app.models import BountyPayment, Report
from app.utils.crypto_address import validate_address as _validate_addr, validate_tx_hash


def utcnow():
    return datetime.now(timezone.utc)


# ── PayPal Payout ─────────────────────────────────────────────────────────────
@bounty_bp.route("/reports/<report_uuid>/bounty/paypal", methods=["POST"])
@owner_required
def paypal_payout(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)

    recipient_email = (request.form.get("recipient_email") or "").strip()
    try:
        amount = float(request.form.get("amount") or 0)
    except (ValueError, TypeError):
        flash("Invalid amount.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    currency = (request.form.get("currency") or "USD").strip().upper()
    note = (request.form.get("note") or f"Bug bounty: {report.display_id}").strip()[:200]

    if not recipient_email or "@" not in recipient_email:
        flash("Valid recipient email required.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    client_id = current_app.config.get("PAYPAL_CLIENT_ID", "")
    client_secret = current_app.config.get("PAYPAL_CLIENT_SECRET", "")
    mode = current_app.config.get("PAYPAL_MODE", "sandbox")

    if not client_id or not client_secret:
        flash("PayPal not configured. Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    payment = BountyPayment(
        report_id=rid,
        method="paypal",
        amount=amount,
        currency=currency,
        paypal_recipient_email=recipient_email,
        status="processing",
        initiated_at=utcnow(),
    )
    db.session.add(payment)
    db.session.flush()
    batch_id = str(payment.id)

    try:
        from app.utils.paypal import initiate_payout
        result = initiate_payout(
            client_id, client_secret, batch_id, recipient_email,
            str(amount), currency,
            report.display_id or batch_id,
            (note or "")[:100], mode
        )
        batch = result
        payment.paypal_payout_batch_id = batch.get("batch_id")
        payment.status = "pending"
        db.session.commit()

        # Queue status polling
        try:
            from app.tasks.bounty import poll_paypal_payout
            poll_paypal_payout.apply_async(
                args=[str(payment.id)], countdown=30)
        except Exception:
            pass

        flash(f"PayPal payout initiated. Batch ID: {payment.paypal_payout_batch_id}", "success")
    except Exception as exc:
        payment.status = "failed"
        payment.error_message = str(exc)[:500]
        db.session.commit()
        current_app.logger.exception("PayPal payout error")
        flash(f"PayPal error: {exc}", "error")

    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


@bounty_bp.route("/reports/<report_uuid>/bounty/paypal/status")
@owner_required
def paypal_status(report_uuid):
    rid = parse_uuid(report_uuid)
    payments = BountyPayment.query.filter_by(
        report_id=rid, method="paypal"
    ).order_by(BountyPayment.initiated_at.desc()).all()
    return jsonify([{
        "id": str(p.id),
        "status": p.status,
        "amount": str(p.amount),
        "currency": p.currency,
        "transaction_id": p.paypal_transaction_id,
        "initiated_at": p.initiated_at.isoformat() if p.initiated_at else None,
        "completed_at": p.completed_at.isoformat() if p.completed_at else None,
    } for p in payments])


# ── Crypto Payment ─────────────────────────────────────────────────────────────
@bounty_bp.route("/reports/<report_uuid>/bounty/crypto", methods=["POST"])
@owner_required
def crypto_record(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)

    try:
        amount = float(request.form.get("amount") or 0)
    except (ValueError, TypeError):
        flash("Invalid amount.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    currency = (request.form.get("currency") or "BTC").strip().upper()
    network = (request.form.get("network") or currency).strip().upper()
    address = (request.form.get("address") or "").strip()
    tx_hash = (request.form.get("tx_hash") or "").strip()

    if address and not _validate_addr(network, address)[0]:
        flash(f"Invalid {network} address format.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    if tx_hash and not validate_tx_hash(tx_hash, network):
        flash(f"Invalid {network} transaction hash format.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    payment = BountyPayment(
        report_id=rid,
        method="crypto",
        amount=amount,
        currency=currency,
        crypto_address=address or None,
        crypto_network=network,
        crypto_tx_hash=tx_hash or None,
        crypto_confirmations=0 if tx_hash else None,
        status="pending" if tx_hash else "processing",
        initiated_at=utcnow(),
    )
    db.session.add(payment)
    db.session.commit()

    if tx_hash and current_app.config.get("CRYPTO_CONFIRM_ENABLED"):
        try:
            from app.tasks.bounty import poll_crypto_confirmation
            poll_crypto_confirmation.apply_async(args=[str(payment.id)], countdown=60)
        except Exception:
            pass

    flash("Crypto payment recorded.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


@bounty_bp.route("/reports/<report_uuid>/bounty/crypto/verify")
@owner_required
def crypto_verify(report_uuid):
    rid = parse_uuid(report_uuid)
    payments = BountyPayment.query.filter_by(
        report_id=rid, method="crypto"
    ).order_by(BountyPayment.initiated_at.desc()).all()
    return jsonify([{
        "id": str(p.id),
        "status": p.status,
        "amount": str(p.amount),
        "currency": p.currency,
        "network": p.crypto_network,
        "tx_hash": p.crypto_tx_hash,
        "confirmations": p.crypto_confirmations,
        "initiated_at": p.initiated_at.isoformat() if p.initiated_at else None,
    } for p in payments])
