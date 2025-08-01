# backend/amazon_viewer/api/orders.py
from flask import Blueprint, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from amazon_viewer.helpers.amazon import get_amazon_session
from amazon_viewer.helpers.ai import summarize_title
from amazonorders.orders import AmazonOrders
from amazonorders.transactions import AmazonTransactions
from datetime import date
import json
import logging

bp = Blueprint('orders', __name__, url_prefix='/api')

@bp.route("/orders", methods=['GET'])
@jwt_required()
def get_orders_and_transactions():
    current_user_id = get_jwt_identity()
    days_to_fetch = request.args.get('days', default=7, type=int)

    def generate_events(user_id, days):
        session = None
        def send_event(event_type, data):
            event_data = json.dumps({"type": event_type, "payload": data})
            yield f"data: {event_data}\n\n"

        try:
            yield from send_event("status", "Initializing Amazon session...")
            session = get_amazon_session(user_id)
            
            # Login is now performed every time
            yield from send_event("status", "Logging into Amazon...")
            session.login()
            yield from send_event("status", "Amazon login successful.")

            amazon_orders = AmazonOrders(session)
            amazon_transactions = AmazonTransactions(session)
            
            yield from send_event("status", f"Fetching transactions for the last {days} days...")
            transactions = amazon_transactions.get_transactions(days=days)
            
            order_numbers = {trans.order_number for trans in transactions if trans.order_number}
            total_orders = len(order_numbers)
            
            yield from send_event("progress_max", total_orders)
            yield from send_event("status", f"Found {total_orders} unique orders to process.")

            processed_orders = 0
            combined_data = []
            for order_num in order_numbers:
                processed_orders += 1
                yield from send_event("status", f"Processing order {processed_orders} of {total_orders} ({order_num})...")
                order_details = amazon_orders.get_order(order_id=order_num)
                
                if order_details and order_details.items:
                    order_data = {
                        "order_number": order_details.order_number,
                        "order_placed_date": order_details.order_placed_date.isoformat() if order_details.order_placed_date else None,
                        "grand_total": f"${order_details.grand_total:.2f}" if order_details.grand_total is not None else None,
                        "items": []
                    }
                    for item in order_details.items:
                        summary = summarize_title(item.title)
                        order_data["items"].append({
                            "title": summary,
                            "link": f"https://www.amazon.com{item.link}" if item.link else None,
                            "price": f"${item.price:.2f}" if item.price is not None else None,
                            "subscription_discount": order_details.subscription_discount
                        })
                    combined_data.append(order_data)
                yield from send_event("progress_update", processed_orders)
            
            combined_data.sort(key=lambda x: x.get('order_placed_date'), reverse=True)
            yield from send_event("data", combined_data)
            yield from send_event("status", "Done.")
        except Exception as e:
            logging.exception("An error occurred while fetching Amazon data.")
            error_msg = str(e) if str(e) else "An unexpected error occurred."
            yield from send_event("error", error_msg)
        finally:
            if session and session.is_authenticated:
                session.logout()

    return Response(generate_events(current_user_id, days_to_fetch), mimetype='text/event-stream')
