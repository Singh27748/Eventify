with open('core/views.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = '''    question = (request.POST.get("question") or "").strip()
    # Print subscription and question to console (for demo purposes)
    print(f"=== NEW SUBSCRIPTION ===")
    print(f"Email: {email}")
    if question:
        print(f"Question: {question}")
    print(f"========================")
    
    if question:
        messages.success(request, "Thank you! Your subscription and question have been submitted to our team.")
    else:
        messages.success(request, "Subscribed successfully! You will receive latest event updates.")
    return redirect("home")'''

new = '''    question = (request.POST.get("question") or "").strip()
    creator_emails = ["asing27748@gmail.com", "vishwakarmaayush3884@gmail.com", "2023bca136@axiscolleges.in"]
    
    if question:
        subject = f"New Subscription and Question from {email}"
        message = f"User Email: {email}\\n\\nQuestion: {question}"
    else:
        subject = f"New Newsletter Subscription from {email}"
        message = f"User Email: {email}"
    
    try:
        from django.core.mail import send_mail
        from django.conf import settings
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@eventify.com')
        send_mail(subject, message, from_email, creator_emails, fail_silently=False)
        messages.success(request, "Thank you! Your subscription has been sent to our team.")
    except Exception as e:
        print(f"Email sending failed: {e}")
        messages.success(request, "Thank you! Your subscription has been submitted.")
    
    return redirect("home")'''

content = content.replace(old, new)

with open('core/views.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('File updated successfully')
