# Eventify - Task Tracking

## Current Tasks

### Security Features Implementation

- [x] Add Security Q/A section in settings.html (templates/core/settings.html)
- [x] Add Account Deletion view in views.py (core/views.py)
- [x] Add URL pattern for account deletion (core/urls.py)
- [x] Add Delete Account button and modal in settings.html (templates/core/settings.html)
- [x] Test the implementation

---

## Completed Tasks

### Private Events Implementation

- [x] Add `is_private` field to Event model (core/models.py)
- [x] Create migration for the new field
- [x] Update dashboard.html to show modal popup
- [x] Update new_event.html with hidden field for event type
- [x] Update new_event view to handle is_private
- [x] Update edit_event view to handle is_private
- [x] Update event_detail.html to show private/public badge

### Bug Fixes

- [x] Fix new_event view to handle guest_emails and active_participant_emails
- [x] Fix edit_event view to include is_private in update_fields
- [x] Fix edit_event view to handle guest_emails and active_participant_emails
