// frontend/src/components/OrdersTable.js

import React from 'react';

function OrdersTable({ data }) {
  if (!data || data.length === 0) {
    return <p>No orders found for the selected date range.</p>;
  }

  return (
    <div className="table-container" style={{ maxWidth: '1000px', margin: '20px auto' }}>
      <table className="table">
        <thead>
          <tr>
            <th>Item</th>
            <th style={{ width: '80px', textAlign: 'center' }}>Qty</th>
            <th style={{ width: '120px' }}>Price</th>
          </tr>
        </thead>
        <tbody>
          {data.map((order) => (
            <React.Fragment key={order.order_number}>
              {/* Header row for the order group */}
              <tr className="order-group-header">
                <td colSpan="3">
                  <div className="order-details">
                    {/* Left-aligned details */}
                    <div className="order-details-group">
                      <div className="order-details-group">
                        <strong>Order #:</strong>
                        <span>{order.order_number}</span>
                      </div>
                      <div className="order-details-group" style={{ marginLeft: '30px' }}>
                        <strong>Date:</strong>
                        <span>{new Date(order.order_placed_date).toLocaleDateString()}</span>
                      </div>
                      {/* ADDED: Display the recipient */}
                      <div className="order-details-group" style={{ marginLeft: '30px' }}>
                        <strong>To:</strong>
                        <span>{order.recipient}</span>
                      </div>
                    </div>

                    {/* Right-aligned details */}
                    <div className="order-details-group">
                      {order.subscription_discount && (
                        <span className="badge badge-warning">
                          {order.subscription_discount}
                        </span>
                      )}
                      <strong>Total:</strong>
                      <span>{order.grand_total}</span>
                    </div>
                  </div>
                </td>
              </tr>
              
              {/* Item rows for this order */}
              {order.items.map((item, itemIndex) => (
                <tr key={`${order.order_number}-${itemIndex}`}>
                  <td>
                    <a href={item.link} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary-color)', textDecoration: 'none' }}>
                      {item.title}
                    </a>
                  </td>
                  <td style={{ textAlign: 'center' }}>{item.quantity}</td>
                  <td>{item.price}</td>
                </tr>
              ))}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default OrdersTable;
