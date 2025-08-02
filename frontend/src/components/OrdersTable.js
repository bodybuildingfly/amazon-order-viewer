// frontend/src/components/OrdersTable.js

import React, { useState } from 'react';

function OrdersTable({ data }) {
  // State to keep track of which order is currently expanded.
  // We store the order_number of the expanded order, or null if none are open.
  const [expandedOrder, setExpandedOrder] = useState(null);

  if (!data || data.length === 0) {
    return <p>No orders found for the selected date range.</p>;
  }

  // Function to toggle which order is expanded
  const handleToggle = (orderNumber) => {
    // If the clicked order is already open, close it. Otherwise, open it.
    setExpandedOrder(expandedOrder === orderNumber ? null : orderNumber);
  };

  return (
    <div style={{ maxWidth: '900px', margin: '20px auto' }}>
      {/* Map over each order to create an accordion item */}
      {data.map((order) => (
        <div key={order.order_number} style={{ border: '1px solid #ccc', borderRadius: '8px', marginBottom: '10px' }}>
          {/* This is the clickable header for each order */}
          <div
            onClick={() => handleToggle(order.order_number)}
            style={{
              padding: '15px',
              backgroundColor: '#f7f7f7',
              cursor: 'pointer',
              display: 'flex', // Use Flexbox for even spacing
              justifyContent: 'space-between', // Distribute items evenly
              alignItems: 'center',
              borderBottom: expandedOrder === order.order_number ? '1px solid #ccc' : 'none'
            }}
          >
            <div>
              <strong>Order #:</strong> {order.order_number}
            </div>
            <div style={{ color: '#555' }}>
              <strong>Placed:</strong> {new Date(order.order_placed_date).toLocaleDateString()}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
              <strong>Total:</strong> {order.grand_total}
              <span style={{ display: 'inline-block', transform: expandedOrder === order.order_number ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>
                ▼
              </span>
            </div>
          </div>

          {/* This is the collapsible content area with the items table */}
          {expandedOrder === order.order_number && (
            <div style={{ padding: '15px' }}>
              {/* Subscribe & Save indicator for the whole order */}
              {order.subscription_discount && (
                <div style={{ marginBottom: '10px' }}>
                  <span style={{
                    backgroundColor: '#ffc107',
                    color: '#212529',
                    padding: '3px 8px',
                    borderRadius: '12px',
                    fontSize: '0.9em',
                    fontWeight: 'bold'
                  }}>
                    Subscribe & Save Discount: {order.subscription_discount}
                  </span>
                </div>
              )}
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid #ddd' }}>
                    <th style={{ padding: '10px', textAlign: 'left' }}>Item Title</th>
                    <th style={{ padding: '10px', textAlign: 'left', width: '120px' }}>Price</th>
                  </tr>
                </thead>
                <tbody>
                  {order.items.map((item, itemIndex) => (
                    <tr key={`${order.order_number}-${itemIndex}`} style={{ borderBottom: '1px solid #eee' }}>
                      <td style={{ padding: '10px', textAlign: 'left' }}>
                        <a href={item.link} target="_blank" rel="noopener noreferrer">
                          {item.title}
                        </a>
                      </td>
                      <td style={{ padding: '10px', textAlign: 'left' }}>{item.price}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export default OrdersTable;
