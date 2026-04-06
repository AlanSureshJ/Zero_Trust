from datetime import datetime, date

TOTAL_FEES = 150000
QUARTER_AMOUNT = TOTAL_FEES / 4

def get_fee_status(fees_paid):
    """
    Returns a dictionary with status of the fees:
    - active_quarter: String name of the quarter
    - expected_paid: Target amount they should have paid by now
    - current_due: Amount due right now (overdue or current quarter)
    - next_due_date: String formatting of next upcoming date (or OVERDUE)
    - total_remaining: Total un-paid balance including future
    """
    now = datetime.now()
    year = now.year
    
    # Define our quarter deadlines (month, day), and their cumulative expected amounts
    quarters = [
        (1, 15, "Q1 - Jan", QUARTER_AMOUNT * 1),
        (4, 15, "Q2 - Apr", QUARTER_AMOUNT * 2),
        (7, 15, "Q3 - Jul", QUARTER_AMOUNT * 3),
        (10, 15, "Q4 - Oct", QUARTER_AMOUNT * 4)
    ]
    
    active_quarter_name = "Q1 - Jan"
    expected_paid = 0
    next_due_date_str = "Jan 15, " + str(year)
    
    # Time loop logic: Determine which quarters have PASSED
    # If a quarter has passed, it bumps the expected_paid up.
    # The first quarter that HAS NOT passed becomes the next due date.
    
    for month, day, name, cumulative in quarters:
        deadline = datetime(year, month, day)
        if now >= deadline:
            expected_paid = cumulative
            # We are inside or past this quarter. Note: once December hits, 
            # they should have paid Q4. Next due date will be calculated below.
        else:
            # First future quarter!
            next_due_date_str = f"{name.split(' - ')[1]} {day}, {year}"
            active_quarter_name = name
            break
            
    # Handle end-of-year wrap around: If passed Oct 15, everything is expected.
    # The next true due date would technically be Jan 15 of NEXT year if they finished.
    if now >= datetime(year, 10, 15):
        next_due_date_str = f"Jan 15, {year + 1}"
        active_quarter_name = "Q4 - Oct"
        
    current_due = max(0, expected_paid - fees_paid)
    total_remaining = max(0, TOTAL_FEES - fees_paid)
    
    # If they owe money now, the due date is ACTUALLY "Immediately"
    actual_due_str = "OVERDUE (Pay Immediately)" if current_due > 0 else next_due_date_str
    
    return {
        "active_quarter": active_quarter_name,
        "expected_paid": expected_paid,
        "current_due": current_due,
        "next_due_date": actual_due_str,
        "total_remaining": total_remaining,
        "total_fees": TOTAL_FEES,
        "is_overdue": current_due > 0
    }
