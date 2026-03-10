# Eventify Feature Status

## Current State

The original 25-feature TODO is outdated. The codebase now covers the combined 28-feature list used for the current Eventify scope.

## Implemented in the Current Build

1. Multi-role login
2. Social login (real Google/GitHub OAuth with env config)
3. Email verification
4. Two-factor authentication (TOTP + backup codes)
5. Smart event search
6. Location-based events
7. Category filters
8. Trending events section
9. Featured events section
10. Create events
11. Edit events
12. Delete events
13. Event schedule management
14. Event capacity control
15. Event image upload
16. Event gallery upload
17. Multiple ticket types
18. QR code ticket generation
19. Digital ticket download (PDF)
20. Ticket cancellation system
21. Online payment integration (Razorpay + local fallback)
22. Payment history
23. Automatic invoice generation
24. Email notifications
25. Event reminder system
26. Attendee management
27. Event analytics dashboard
28. Revenue tracking

## Next Hardening Tasks

1. Gateway webhook reconciliation and automated refund sync
2. Secret-management hardening for OAuth and payment credentials
3. Scheduled background jobs for reminders and mail retries
4. More end-to-end and regression test coverage
5. Deployment hardening for secure cookies, CSRF trusted origins, and production email config
