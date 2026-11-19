// Refund math for partial returns on discounted orders.
// All money in the Shopify order is already net of discounts at line level
// (discountedTotal), so the exact refund for returning `qty` of a line is
// discountedTotal * qty / lineQuantity, plus the same share of the line's tax.

const cents = (n) => Math.round((Number(n) + Number.EPSILON) * 100);
const money = (c) => (c / 100).toFixed(2);

function shareCents(totalCents, qty, lineQty) {
  if (!lineQty) return 0;
  return Math.round((totalCents * qty) / lineQty);
}

// order: { taxesIncluded, lineItems: [{ id, title, variantTitle, quantity,
//   refundableQuantity, originalTotal, discountedTotal, taxTotal }] }
// picks: [{ id, qty }]
function calculateRefund(order, picks) {
  const lines = [];
  let netC = 0;
  let taxC = 0;
  let discountKeptC = 0;

  for (const pick of picks) {
    const qty = Number(pick.qty) || 0;
    if (qty <= 0) continue;
    const li = order.lineItems.find((l) => l.id === pick.id);
    if (!li) throw new Error('Line item not found: ' + pick.id);
    if (qty > li.refundableQuantity) {
      throw new Error(
        'Cannot return ' + qty + ' of "' + li.title + '": only ' + li.refundableQuantity + ' left to refund'
      );
    }
    const orig = cents(li.originalTotal);
    const disc = cents(li.discountedTotal);
    const tax = cents(li.taxTotal);
    const lineNet = shareCents(disc, qty, li.quantity); // what the customer really paid for these units (pre-tax if tax is added on top)
    const lineTax = shareCents(tax, qty, li.quantity);
    const lineOrig = shareCents(orig, qty, li.quantity);
    netC += lineNet;
    taxC += lineTax;
    discountKeptC += lineOrig - lineNet;
    lines.push({
      id: li.id,
      title: li.title,
      variantTitle: li.variantTitle,
      qty,
      listPrice: money(lineOrig),
      paid: money(lineNet),
      tax: money(lineTax),
    });
  }

  // When prices include tax, the paid amount already contains the tax.
  const totalC = order.taxesIncluded ? netC : netC + taxC;
  return {
    lines,
    itemsPaid: money(netC),
    tax: money(taxC),
    taxesIncluded: !!order.taxesIncluded,
    discountShare: money(discountKeptC),
    refundTotal: money(totalC),
  };
}

module.exports = { calculateRefund, cents, money };
