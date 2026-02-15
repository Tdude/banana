<?php
/**
 * Plugin Name: Banana
 * Description: Standalone shortcode form that submits directly to Mailchimp Audience via API.
 * Version: 0.1.0
 * Author: Tibor Berki
 * Text Domain: banana
 */

if (!defined('ABSPATH')) {
    exit;
}

const BANANA_OPTION_KEY = 'banana_options';

function banana_defaults(): array {
    return [
        'api_key' => '',
        'datacenter' => '',
        'audience_id' => '',
        'double_opt_in' => '0',
        'success_message' => __('Tack! Du är nu registrerad.', 'banana'),
    ];
}

function banana_get_options(): array {
    $stored = get_option(BANANA_OPTION_KEY, []);
    if (!is_array($stored)) {
        $stored = [];
    }

    $options = wp_parse_args($stored, banana_defaults());

    return $options;
}

function banana_sanitize_options($input): array {
    $defaults = banana_defaults();
    $input = is_array($input) ? $input : [];

    $datacenter = isset($input['datacenter']) ? strtolower(sanitize_text_field((string) $input['datacenter'])) : $defaults['datacenter'];
    if ($datacenter !== '' && !preg_match('/^[a-z]{2}\d+$/', $datacenter)) {
        $datacenter = $defaults['datacenter'];
    }

    $audience_id = isset($input['audience_id']) ? sanitize_text_field((string) $input['audience_id']) : $defaults['audience_id'];
    if ($audience_id !== '' && !preg_match('/^[a-zA-Z0-9]+$/', $audience_id)) {
        $audience_id = $defaults['audience_id'];
    }

    return [
        'api_key' => isset($input['api_key']) ? sanitize_text_field((string) $input['api_key']) : $defaults['api_key'],
        'datacenter' => $datacenter,
        'audience_id' => $audience_id,
        'double_opt_in' => !empty($input['double_opt_in']) ? '1' : '0',
        'success_message' => isset($input['success_message']) ? sanitize_text_field((string) $input['success_message']) : $defaults['success_message'],
    ];
}

function banana_register_settings(): void {
    register_setting('banana_settings_group', BANANA_OPTION_KEY, [
        'sanitize_callback' => 'banana_sanitize_options',
    ]);
}
add_action('admin_init', 'banana_register_settings');

function banana_add_settings_page(): void {
    add_management_page(
        __('Banana', 'banana'),
        __('Banana', 'banana'),
        'manage_options',
        'banana',
        'banana_render_settings_page'
    );
}
add_action('admin_menu', 'banana_add_settings_page');

function banana_render_settings_page(): void {
    if (!current_user_can('manage_options')) {
        return;
    }

    $options = banana_get_options();
    ?>
    <div class="wrap">
        <h1><?php echo esc_html__('Banana', 'banana'); ?></h1>
        <p><?php echo esc_html__('Use shortcode [banana_form] anywhere you want to render the form.', 'banana'); ?></p>

        <form method="post" action="options.php">
            <?php settings_fields('banana_settings_group'); ?>

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="banana_api_key"><?php echo esc_html__('Mailchimp API key', 'banana'); ?></label></th>
                    <td><input type="password" id="banana_api_key" name="<?php echo esc_attr(BANANA_OPTION_KEY); ?>[api_key]" value="<?php echo esc_attr((string) $options['api_key']); ?>" class="regular-text" autocomplete="off" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="banana_datacenter"><?php echo esc_html__('Datacenter', 'banana'); ?></label></th>
                    <td>
                        <input type="text" id="banana_datacenter" name="<?php echo esc_attr(BANANA_OPTION_KEY); ?>[datacenter]" value="<?php echo esc_attr((string) $options['datacenter']); ?>" class="regular-text" placeholder="us1" />
                        <p class="description"><?php echo esc_html__('Example: us1, us18, eu1.', 'banana'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="banana_audience_id"><?php echo esc_html__('Audience (List) ID', 'banana'); ?></label></th>
                    <td><input type="text" id="banana_audience_id" name="<?php echo esc_attr(BANANA_OPTION_KEY); ?>[audience_id]" value="<?php echo esc_attr((string) $options['audience_id']); ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><?php echo esc_html__('Double opt-in', 'banana'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(BANANA_OPTION_KEY); ?>[double_opt_in]" value="1" <?php checked($options['double_opt_in'], '1'); ?> />
                            <?php echo esc_html__('Require confirmation email (pending status for new contacts).', 'banana'); ?>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="banana_success_message"><?php echo esc_html__('Success message', 'banana'); ?></label></th>
                    <td><input type="text" id="banana_success_message" name="<?php echo esc_attr(BANANA_OPTION_KEY); ?>[success_message]" value="<?php echo esc_attr((string) $options['success_message']); ?>" class="regular-text" /></td>
                </tr>
            </table>

            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

function banana_get_current_url(): string {
    $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '/';
    return home_url($request_uri);
}

function banana_redirect_with_status(string $status, string $message = ''): void {
    $target = remove_query_arg(['mcf_status', 'mcf_msg'], wp_get_referer() ?: banana_get_current_url());
    $target = add_query_arg('mcf_status', $status, $target);

    if ($message !== '') {
        $target = add_query_arg('mcf_msg', rawurlencode($message), $target);
    }

    wp_safe_redirect($target);
    exit;
}

function banana_render_form_shortcode(): string {
    $status = isset($_GET['mcf_status']) ? sanitize_key((string) wp_unslash($_GET['mcf_status'])) : '';
    $message = isset($_GET['mcf_msg']) ? sanitize_text_field(rawurldecode((string) wp_unslash($_GET['mcf_msg']))) : '';

    $captcha_token = apply_filters('banana_captcha_token', '');

    ob_start();
    ?>
    <form method="post" action="">
        <?php wp_nonce_field('banana_submit', 'banana_nonce'); ?>
        <input type="hidden" name="procaptcha" value="<?php echo esc_attr((string) $captcha_token); ?>" />
        <input type="text" name="website" value="" tabindex="-1" autocomplete="off" style="position:absolute; left:-9999px;" aria-hidden="true" />

        <?php if ($status === 'success') : ?>
            <p style="color:green;"><?php echo esc_html($message !== '' ? $message : __('Tack! Du är nu registrerad.', 'banana')); ?></p>
        <?php elseif ($status === 'error') : ?>
            <p style="color:red;"><?php echo esc_html($message !== '' ? $message : __('Något gick fel. Försök igen.', 'banana')); ?></p>
        <?php endif; ?>

        <p>
            <label for="banana_name"><?php echo esc_html__('Namn:', 'banana'); ?>
                <input type="text" id="banana_name" name="NAME" placeholder="<?php echo esc_attr__('Ditt namn', 'banana'); ?>" required />
            </label>
        </p>

        <p>
            <label for="banana_email"><?php echo esc_html__('E-postadress:', 'banana'); ?>
                <input type="email" id="banana_email" name="EMAIL" placeholder="<?php echo esc_attr__('Din e-postadress', 'banana'); ?>" required />
            </label>
        </p>

        <p>
            <label for="banana_title"><?php echo esc_html__('Rubrik:', 'banana'); ?>
                <input type="text" id="banana_title" name="TITLE" placeholder="<?php echo esc_attr__('Vad gäller det?', 'banana'); ?>" required />
            </label>
        </p>

        <p>
            <label for="banana_message"><?php echo esc_html__('Meddelande:', 'banana'); ?>
                <textarea id="banana_message" name="MESSAGE" placeholder="<?php echo esc_attr__('Ditt meddelande', 'banana'); ?>" required></textarea>
            </label>
        </p>

        <p>
            <input type="submit" name="submit_mailchimp" value="<?php echo esc_attr__('Skicka', 'banana'); ?>" />
        </p>
    </form>
    <?php
    return (string) ob_get_clean();
}
add_shortcode('banana_form', 'banana_render_form_shortcode');

function banana_handle_submission(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    if (!isset($_POST['submit_mailchimp'], $_POST['banana_nonce'])) {
        return;
    }

    if (!wp_verify_nonce(sanitize_text_field((string) wp_unslash($_POST['banana_nonce'])), 'banana_submit')) {
        banana_redirect_with_status('error', __('Ogiltig formulärsäkerhet.', 'banana'));
    }

    $honeypot = isset($_POST['website']) ? trim((string) wp_unslash($_POST['website'])) : '';
    if ($honeypot !== '') {
        banana_redirect_with_status('success');
    }

    $captcha_token = isset($_POST['procaptcha']) ? sanitize_text_field((string) wp_unslash($_POST['procaptcha'])) : '';
    $captcha_valid = (bool) apply_filters('banana_validate_captcha', true, $captcha_token, $_POST);
    if (!$captcha_valid) {
        banana_redirect_with_status('error', __('Ogiltig CAPTCHA.', 'banana'));
    }

    $email = isset($_POST['EMAIL']) ? sanitize_email((string) wp_unslash($_POST['EMAIL'])) : '';
    if (!is_email($email)) {
        banana_redirect_with_status('error', __('Ogiltig e-postadress.', 'banana'));
    }

    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
    $email_key = 'banana_rl_email_' . md5(strtolower(trim($email)));
    $ip_key = $ip !== '' ? 'banana_rl_ip_' . md5($ip) : '';

    $email_count = (int) get_transient($email_key);
    if ($email_count >= 3) {
        banana_redirect_with_status('error', __('För många försök. Försök igen om en stund.', 'banana'));
    }

    if ($ip_key !== '') {
        $ip_count = (int) get_transient($ip_key);
        if ($ip_count >= 10) {
            banana_redirect_with_status('error', __('För många försök. Försök igen om en stund.', 'banana'));
        }
    }

    set_transient($email_key, $email_count + 1, 60);
    if ($ip_key !== '') {
        set_transient($ip_key, $ip_count + 1, 60);
    }

    $name = isset($_POST['NAME']) ? sanitize_text_field((string) wp_unslash($_POST['NAME'])) : '';
    $title = isset($_POST['TITLE']) ? sanitize_text_field((string) wp_unslash($_POST['TITLE'])) : '';
    $message = isset($_POST['MESSAGE']) ? sanitize_textarea_field((string) wp_unslash($_POST['MESSAGE'])) : '';

    $options = banana_get_options();

    if ($options['api_key'] === '' || $options['datacenter'] === '' || $options['audience_id'] === '') {
        banana_redirect_with_status('error', __('Mailchimp är inte korrekt konfigurerat.', 'banana'));
    }

    $subscriber_hash = md5(strtolower(trim($email)));
    $endpoint = sprintf(
        'https://%1$s.api.mailchimp.com/3.0/lists/%2$s/members/%3$s',
        rawurlencode($options['datacenter']),
        rawurlencode($options['audience_id']),
        $subscriber_hash
    );

    $merge_fields = [
        'FNAME' => $name,
        'TITLE' => $title,
        'MESSAGE' => $message,
    ];

    $merge_fields = apply_filters('banana_merge_fields', $merge_fields, [
        'name' => $name,
        'title' => $title,
        'message' => $message,
        'email' => $email,
    ]);

    $payload = [
        'email_address' => $email,
        'status_if_new' => $options['double_opt_in'] === '1' ? 'pending' : 'subscribed',
        'status' => 'subscribed',
        'merge_fields' => $merge_fields,
    ];

    $response = wp_remote_request($endpoint, [
        'method' => 'PUT',
        'timeout' => 30,
        'headers' => [
            'Authorization' => 'Basic ' . base64_encode('user:' . $options['api_key']),
            'Content-Type' => 'application/json',
        ],
        'body' => wp_json_encode($payload),
    ]);

    if (is_wp_error($response)) {
        banana_redirect_with_status('error', __('API-fel. Försök igen senare.', 'banana'));
    }

    $code = (int) wp_remote_retrieve_response_code($response);
    if ($code === 200 || $code === 201) {
        $success_msg = $options['success_message'] !== '' ? (string) $options['success_message'] : __('Tack! Du är nu registrerad.', 'banana');
        banana_redirect_with_status('success', $success_msg);
    }

    $response_body = json_decode((string) wp_remote_retrieve_body($response), true);
    $error_detail = '';
    if (is_array($response_body)) {
        if (!empty($response_body['detail'])) {
            $error_detail = sanitize_text_field((string) $response_body['detail']);
        } elseif (!empty($response_body['title'])) {
            $error_detail = sanitize_text_field((string) $response_body['title']);
        }
    }

    banana_redirect_with_status('error', $error_detail !== '' ? $error_detail : __('Ett okänt fel uppstod.', 'banana'));
}
add_action('init', 'banana_handle_submission');
