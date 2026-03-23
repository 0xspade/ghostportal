# GhostPortal bounty tasks
# Copyright (C) 2026 Spade - AGPL-3.0
import logging
from datetime import datetime, timezone
from app.extensions import celery

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=5)
def poll_crypto_confirmation(self, payment_id):
    import uuid
    from app.models import BountyPayment
    from app.extensions import db
    from app.utils.crypto_confirm import check_confirmations, get_min_confirmations
    try:
        pid = uuid.UUID(payment_id)
        payment = BountyPayment.query.get(pid)
        if not payment or payment.status == "completed":
            return
        confirmations = check_confirmations(
            payment.crypto_network or "ETH",
            payment.crypto_tx_hash or "",
        )
        if confirmations is not None:
            payment.crypto_confirmations = confirmations
            min_conf = get_min_confirmations(payment.crypto_network or "ETH")
            if confirmations >= min_conf:
                payment.status = "completed"
                payment.completed_at = datetime.now(timezone.utc)
            db.session.add(payment)
            db.session.commit()
    except Exception as exc:
        logger.error(f"Crypto confirmation poll failed: {exc}")
        try:
            self.retry(exc=exc, countdown=300)
        except Exception:
            pass


@celery.task(bind=True, max_retries=10, default_retry_delay=60)
def poll_paypal_payout(self, payment_id):
    """Poll PayPal for payout status updates."""
    import uuid as _uuid
    from app.models import BountyPayment
    from app.extensions import db
    import logging
    logger = logging.getLogger(__name__)

    try:
        pid = _uuid.UUID(str(payment_id))
        payment = BountyPayment.query.get(pid)
        if not payment:
            logger.warning(f"poll_paypal_payout: payment {payment_id} not found")
            return
        if payment.status in ("completed", "failed", "refunded"):
            return  # terminal state, stop polling

        from app.utils.paypal import get_payout_item_status
        status_data = get_payout_item_status(
            payment.paypal_payout_batch_id,
            payment.paypal_item_id,
        )
        transaction_status = (status_data.get("transaction_status") or "").upper()

        if transaction_status in ("SUCCESS", "UNCLAIMED"):
            payment.status = "completed"
            payment.paypal_transaction_id = status_data.get("transaction_id", "")
            from datetime import datetime, timezone
            payment.completed_at = datetime.now(timezone.utc)
            db.session.commit()
            logger.info(f"PayPal payout {payment_id} completed")
        elif transaction_status in ("FAILED", "RETURNED", "BLOCKED", "REFUNDED"):
            payment.status = "failed"
            payment.error_message = status_data.get("errors", {}).get("message", transaction_status)
            db.session.commit()
            logger.warning(f"PayPal payout {payment_id} failed: {payment.error_message}")
        else:
            # Still pending — retry
            raise self.retry()
    except Exception as exc:
        if not isinstance(exc, self.MaxRetriesExceededError if hasattr(self, 'MaxRetriesExceededError') else type(None)):
            logger.error(f"poll_paypal_payout error: {exc}", exc_info=True)
        raise self.retry(exc=exc)
