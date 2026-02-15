# Banana (WordPress Plugin)

Banana is a lightweight WordPress plugin that renders a shortcode-based form and submits entries directly to a Mailchimp Audience via the Mailchimp API.

## For site owners / editors

### Install

1. Upload the `banana` folder to:

   `wp-content/plugins/`

2. In WordPress admin, go to:

   `Plugins -> Installed Plugins`

3. Activate **Banana**.

### Configure Mailchimp

1. In WordPress admin, go to:

   `Tools -> Banana`

2. Fill in:

   - **Mailchimp API key**
   - **Datacenter** (example: `us1`, `us18`, `eu1`)
   - **Audience (List) ID**
   - **Double opt-in** (optional)
   - **Success message** (optional)

3. Save changes.

### Use the form

Add the shortcode anywhere you want the form to appear:

- `[banana_form]`

### What the form collects

The form sends these fields to Mailchimp:

- `EMAIL` (required)
- `NAME`
- `TITLE`
- `MESSAGE`

These are sent as Mailchimp merge fields:

- `FNAME` <- `NAME`
- `TITLE` <- `TITLE`
- `MESSAGE` <- `MESSAGE`

### Basic anti-abuse protections

Banana includes low-friction spam/abuse protections:

- Honeypot field (`website`)
- Nonce verification
- Lightweight rate limiting (short bursts)

If someone submits too many times in a short period, they will see a “try again later” message.

---

## Developer notes

### File structure

- `banana.php` contains the full plugin implementation.

### Admin page

- Settings page is registered under `Tools -> Banana` via `add_management_page()`.
- Settings are stored in a single option:

  - Option key: `banana_options`

### Shortcode

- Shortcode: `[banana_form]`
- Handler: `banana_render_form_shortcode()`

### Hooks / extension points

Banana provides a few filters to integrate additional protection or custom merge field behavior:

- `banana_captcha_token`

  Used to inject a CAPTCHA token into the hidden `procaptcha` field.

- `banana_validate_captcha`

  Used to validate CAPTCHA on submit.

  Signature:

  - `apply_filters('banana_validate_captcha', true, $captcha_token, $_POST)`

- `banana_merge_fields`

  Used to modify merge fields before sending to Mailchimp.

  Signature:

  - `apply_filters('banana_merge_fields', $merge_fields, $context)`

  Where `$context` contains:

  - `name`, `title`, `message`, `email`

### Mailchimp API behavior

- Uses a `PUT` request to:

  `https://{datacenter}.api.mailchimp.com/3.0/lists/{audience_id}/members/{subscriber_hash}`

- `subscriber_hash` is the MD5 of the lowercased email.
- Sets:

  - `status_if_new` to `pending` if double opt-in is enabled, otherwise `subscribed`
  - `status` to `subscribed`

### Rate limiting implementation

Rate limiting is implemented with transients in `banana_handle_submission()`:

- Per-email: max `3` per `60s`
- Per-IP: max `10` per `60s`

Transient keys:

- `banana_rl_email_{md5(email)}`
- `banana_rl_ip_{md5(ip)}`

### Translations

- Text domain: `banana`

