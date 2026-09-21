<?php
/**
 * Plugin Name: Ishi Social AI Gateway
 * Description: Secure asynchronous bridge from ManyChat social messages to AI Engine, with conversation continuity, idempotency, rate limiting, human handoff state, and ManyChat reply delivery.
 * Version: 1.0.0
 * Author: Ishi Nail Lab
 * Requires at least: 6.9
 * Requires PHP: 8.0
 */

namespace Ishi\SocialAI;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class Gateway {
    private const VERSION = '1.0.0';
    private const OPTION  = 'ishi_social_ai_gateway_settings';
    private const TOKEN_HASH_OPTION = 'ishi_social_ai_gateway_token_hash';
    private const TOKEN_NOTICE_PREFIX = 'ishi_social_ai_gateway_token_notice_';
    private const REST_NS = 'ishi-social-ai/v1';
    private const PROCESS_HOOK = 'ishi_social_ai_process_message';

    private const MAX_MESSAGE_CHARS = 4000;
    private const IDEMPOTENCY_TTL   = DAY_IN_SECONDS;
    private const FALLBACK_DEDUPE_TTL = 15;
    private const HANDOFF_TTL       = 7 * DAY_IN_SECONDS;

    public static function boot(): void {
        add_action( 'rest_api_init', [ __CLASS__, 'register_routes' ] );
        add_action( 'admin_menu', [ __CLASS__, 'admin_menu' ] );
        add_action( 'admin_init', [ __CLASS__, 'register_settings' ] );
        add_action( 'admin_post_ishi_social_ai_rotate_token', [ __CLASS__, 'rotate_token' ] );
        add_action( self::PROCESS_HOOK, [ __CLASS__, 'process_queued_message' ], 10, 1 );
    }

    public static function activate(): void {
        $defaults = [
            'bot_id'              => 'default',
            'manychat_api_key'    => '',
            'per_contact_limit'   => 12,
            'global_limit'        => 120,
            'max_reply_instagram' => 950,
            'max_reply_default'   => 1800,
        ];
        if ( false === get_option( self::OPTION, false ) ) {
            add_option( self::OPTION, $defaults, '', false );
        }
    }

    public static function register_routes(): void {
        register_rest_route(
            self::REST_NS,
            '/message',
            [
                'methods'             => 'POST',
                'callback'            => [ __CLASS__, 'receive_message' ],
                'permission_callback' => [ __CLASS__, 'authenticate_request' ],
            ]
        );

        register_rest_route(
            self::REST_NS,
            '/state',
            [
                'methods'             => 'POST',
                'callback'            => [ __CLASS__, 'set_conversation_state' ],
                'permission_callback' => [ __CLASS__, 'authenticate_request' ],
            ]
        );

        register_rest_route(
            self::REST_NS,
            '/health',
            [
                'methods'             => 'GET',
                'callback'            => [ __CLASS__, 'health' ],
                'permission_callback' => [ __CLASS__, 'authenticate_request' ],
            ]
        );
    }

    public static function authenticate_request( WP_REST_Request $request ) {
        $stored_hash = self::gateway_token_hash();
        if ( '' === $stored_hash ) {
            return new WP_Error( 'ishi_gateway_not_configured', 'Gateway authentication is not configured.', [ 'status' => 503 ] );
        }

        $header = trim( (string) $request->get_header( 'authorization' ) );
        if ( ! preg_match( '/^Bearer\s+(.+)$/i', $header, $matches ) ) {
            return new WP_Error( 'ishi_gateway_unauthorized', 'Unauthorized.', [ 'status' => 401 ] );
        }

        $provided_hash = hash( 'sha256', trim( $matches[1] ) );
        if ( ! hash_equals( $stored_hash, $provided_hash ) ) {
            return new WP_Error( 'ishi_gateway_unauthorized', 'Unauthorized.', [ 'status' => 401 ] );
        }

        return true;
    }

    public static function receive_message( WP_REST_Request $request ): WP_REST_Response|WP_Error {
        $payload = self::normalize_payload( $request->get_json_params() ?: [] );
        if ( is_wp_error( $payload ) ) {
            return $payload;
        }

        $rate = self::check_rate_limits( $payload['conversation_key'] );
        if ( is_wp_error( $rate ) ) {
            return $rate;
        }

        if ( 'human_active' === self::get_state( $payload['conversation_key'] ) ) {
            return self::json_response(
                [
                    'accepted' => false,
                    'status'   => 'human_active',
                    'handoff'  => true,
                ]
            );
        }

        $dedupe_key = self::dedupe_key( $payload );
        if ( get_transient( $dedupe_key ) ) {
            return self::json_response(
                [
                    'accepted' => true,
                    'status'   => 'duplicate_ignored',
                    'handoff'  => false,
                ]
            );
        }
        set_transient( $dedupe_key, 1, ! empty( $payload['message_id'] ) ? self::IDEMPOTENCY_TTL : self::FALLBACK_DEDUPE_TTL );

        $job_id = wp_generate_uuid4();
        set_transient( 'ishi_social_job_' . md5( $job_id ), $payload, HOUR_IN_SECONDS );

        if ( function_exists( 'as_enqueue_async_action' ) ) {
            as_enqueue_async_action( self::PROCESS_HOOK, [ $job_id ], 'ishi-social-ai' );
        } else {
            wp_schedule_single_event( time() + 1, self::PROCESS_HOOK, [ $job_id ] );
            if ( function_exists( 'spawn_cron' ) ) {
                spawn_cron();
            }
        }

        return self::json_response(
            [
                'accepted' => true,
                'status'   => 'queued',
                'handoff'  => false,
            ]
        );
    }

    public static function process_queued_message( string $job_id ): void {
        $key     = 'ishi_social_job_' . md5( $job_id );
        $payload = get_transient( $key );
        delete_transient( $key );

        if ( ! is_array( $payload ) ) {
            return;
        }

        if ( 'human_active' === self::get_state( $payload['conversation_key'] ) ) {
            return;
        }

        global $mwai;
        if ( ! is_object( $mwai ) || ! method_exists( $mwai, 'simpleChatbotQuery' ) ) {
            self::log_error( 'ai_engine_unavailable', $payload['conversation_key'] );
            return;
        }

        $bot_id  = self::settings()['bot_id'] ?: 'default';
        $chat_id = 'ishi_social_' . substr( hash_hmac( 'sha256', $payload['conversation_key'], self::hash_secret() ), 0, 40 );

        $context = self::trusted_context( $payload );
        $filter = static function ( $instructions, $query ) use ( $context ) {
            return rtrim( (string) $instructions ) . "\n\n" . $context;
        };

        add_filter( 'mwai_ai_instructions', $filter, 999, 2 );

        try {
            $reply = $mwai->simpleChatbotQuery(
                $bot_id,
                $payload['message'],
                [ 'chatId' => $chat_id ],
                true
            );
        } catch ( \Throwable $e ) {
            remove_filter( 'mwai_ai_instructions', $filter, 999 );
            self::log_error( 'ai_query_failed:' . get_class( $e ), $payload['conversation_key'] );
            return;
        }

        remove_filter( 'mwai_ai_instructions', $filter, 999 );

        $reply = self::extract_reply_text( $reply );
        if ( '' === $reply ) {
            self::log_error( 'empty_ai_reply', $payload['conversation_key'] );
            return;
        }

        $reply = self::limit_reply( $reply, $payload['channel'] );
        self::send_manychat_reply( $payload, $reply );
    }

    public static function set_conversation_state( WP_REST_Request $request ): WP_REST_Response|WP_Error {
        $data       = $request->get_json_params() ?: [];
        $channel    = self::normalize_channel( $data['channel'] ?? '' );
        $contact_id = sanitize_text_field( (string) ( $data['contact_id'] ?? '' ) );
        $state      = sanitize_key( (string) ( $data['state'] ?? '' ) );

        if ( ! $channel || '' === $contact_id ) {
            return new WP_Error( 'ishi_gateway_invalid_state_request', 'channel and contact_id are required.', [ 'status' => 400 ] );
        }
        if ( ! in_array( $state, [ 'ai_active', 'human_active' ], true ) ) {
            return new WP_Error( 'ishi_gateway_invalid_state', 'state must be ai_active or human_active.', [ 'status' => 400 ] );
        }

        $conversation_key = $channel . ':' . $contact_id;
        if ( 'human_active' === $state ) {
            set_transient( self::state_key( $conversation_key ), 'human_active', self::HANDOFF_TTL );
        } else {
            delete_transient( self::state_key( $conversation_key ) );
        }

        return self::json_response( [ 'ok' => true, 'state' => $state ] );
    }

    public static function health( WP_REST_Request $request ): WP_REST_Response {
        global $mwai;
        return self::json_response(
            [
                'ok'                 => true,
                'version'            => self::VERSION,
                'ai_engine_ready'    => is_object( $mwai ) && method_exists( $mwai, 'simpleChatbotQuery' ),
                'manychat_key_ready' => '' !== self::manychat_api_key(),
                'queue'              => function_exists( 'as_enqueue_async_action' ) ? 'action_scheduler' : 'wp_cron',
            ]
        );
    }

    private static function normalize_payload( array $data ) {
        $channel = self::normalize_channel( $data['channel'] ?? '' );
        if ( ! $channel ) {
            return new WP_Error( 'ishi_gateway_invalid_channel', 'Unsupported channel.', [ 'status' => 400 ] );
        }

        $contact_id = sanitize_text_field( (string) ( $data['contact_id'] ?? '' ) );
        $message    = trim( wp_strip_all_tags( (string) ( $data['message'] ?? '' ) ) );
        $message_id = sanitize_text_field( (string) ( $data['message_id'] ?? '' ) );
        $first_name = sanitize_text_field( (string) ( $data['first_name'] ?? '' ) );
        $language   = sanitize_text_field( (string) ( $data['language'] ?? '' ) );

        if ( '' === $contact_id || '' === $message ) {
            return new WP_Error( 'ishi_gateway_missing_fields', 'contact_id and message are required.', [ 'status' => 400 ] );
        }

        if ( function_exists( 'mb_strlen' ) ? mb_strlen( $message ) > self::MAX_MESSAGE_CHARS : strlen( $message ) > self::MAX_MESSAGE_CHARS ) {
            return new WP_Error( 'ishi_gateway_message_too_long', 'Message is too long.', [ 'status' => 413 ] );
        }

        return [
            'channel'          => $channel,
            'contact_id'       => $contact_id,
            'message_id'       => $message_id,
            'first_name'       => $first_name,
            'language'         => $language,
            'message'          => $message,
            'conversation_key' => $channel . ':' . $contact_id,
        ];
    }

    private static function normalize_channel( $channel ): string {
        $channel = strtolower( sanitize_key( (string) $channel ) );
        $aliases = [ 'facebook' => 'messenger', 'fb' => 'messenger', 'ig' => 'instagram' ];
        $channel = $aliases[ $channel ] ?? $channel;
        return in_array( $channel, [ 'instagram', 'messenger', 'whatsapp', 'telegram' ], true ) ? $channel : '';
    }

    private static function check_rate_limits( string $conversation_key ) {
        $settings = self::settings();
        $per_contact_limit = max( 1, (int) $settings['per_contact_limit'] );
        $global_limit      = max( 1, (int) $settings['global_limit'] );

        $bucket = gmdate( 'YmdHi' );
        $contact_key = 'ishi_social_rl_c_' . md5( $conversation_key . '|' . $bucket );
        $global_key  = 'ishi_social_rl_g_' . $bucket;

        $contact_count = (int) get_transient( $contact_key );
        $global_count  = (int) get_transient( $global_key );

        if ( $contact_count >= $per_contact_limit || $global_count >= $global_limit ) {
            return new WP_Error( 'ishi_gateway_rate_limited', 'Too many requests.', [ 'status' => 429 ] );
        }

        set_transient( $contact_key, $contact_count + 1, 2 * MINUTE_IN_SECONDS );
        set_transient( $global_key, $global_count + 1, 2 * MINUTE_IN_SECONDS );
        return true;
    }

    private static function dedupe_key( array $payload ): string {
        if ( '' !== $payload['message_id'] ) {
            $fingerprint = 'id|' . $payload['channel'] . '|' . $payload['message_id'];
        } else {
            $fingerprint = 'fallback|' . $payload['conversation_key'] . '|' . $payload['message'];
        }
        return 'ishi_social_dedupe_' . hash( 'sha256', $fingerprint );
    }

    private static function trusted_context( array $payload ): string {
        $parts = [
            '## Trusted social-channel context',
            'This metadata is supplied by the Ishi server, not by the customer. Use it only to adapt communication; do not reveal internal identifiers.',
            'Channel: ' . $payload['channel'],
        ];
        if ( '' !== $payload['first_name'] ) {
            $parts[] = 'Customer first name: ' . $payload['first_name'];
        }
        if ( '' !== $payload['language'] ) {
            $parts[] = 'Platform language: ' . $payload['language'];
        }
        $parts[] = 'Social replies should normally be concise and easy to read on mobile.';
        return implode( "\n", $parts );
    }

    private static function extract_reply_text( $reply ): string {
        if ( is_string( $reply ) ) {
            return trim( wp_strip_all_tags( $reply ) );
        }
        if ( is_array( $reply ) ) {
            foreach ( [ 'reply', 'text', 'content', 'message' ] as $key ) {
                if ( isset( $reply[ $key ] ) && is_string( $reply[ $key ] ) ) {
                    return trim( wp_strip_all_tags( $reply[ $key ] ) );
                }
            }
        }
        if ( is_object( $reply ) ) {
            foreach ( [ 'reply', 'text', 'content', 'message' ] as $key ) {
                if ( isset( $reply->{$key} ) && is_string( $reply->{$key} ) ) {
                    return trim( wp_strip_all_tags( $reply->{$key} ) );
                }
            }
        }
        return '';
    }

    private static function limit_reply( string $reply, string $channel ): string {
        $settings = self::settings();
        $max = 'instagram' === $channel ? (int) $settings['max_reply_instagram'] : (int) $settings['max_reply_default'];
        $max = max( 200, $max );
        $length = function_exists( 'mb_strlen' ) ? mb_strlen( $reply ) : strlen( $reply );
        if ( $length <= $max ) {
            return $reply;
        }
        if ( function_exists( 'mb_substr' ) ) {
            return rtrim( mb_substr( $reply, 0, $max - 1 ) ) . '…';
        }
        return rtrim( substr( $reply, 0, $max - 1 ) ) . '…';
    }

    private static function send_manychat_reply( array $payload, string $reply ): void {
        $api_key = self::manychat_api_key();
        if ( '' === $api_key ) {
            self::log_error( 'manychat_api_key_missing', $payload['conversation_key'] );
            return;
        }

        $content = [
            'messages' => [
                [
                    'type' => 'text',
                    'text' => $reply,
                ],
            ],
        ];
        if ( in_array( $payload['channel'], [ 'instagram', 'whatsapp', 'telegram' ], true ) ) {
            $content['type'] = $payload['channel'];
        }

        $body = [
            'subscriber_id' => is_numeric( $payload['contact_id'] ) ? (int) $payload['contact_id'] : $payload['contact_id'],
            'data'          => [
                'version' => 'v2',
                'content' => $content,
            ],
        ];

        $response = wp_remote_post(
            'https://api.manychat.com/fb/sending/sendContent',
            [
                'timeout' => 10,
                'headers' => [
                    'Authorization' => 'Bearer ' . $api_key,
                    'Accept'        => 'application/json',
                    'Content-Type'  => 'application/json',
                ],
                'body' => wp_json_encode( $body ),
            ]
        );

        if ( is_wp_error( $response ) ) {
            self::log_error( 'manychat_transport_error', $payload['conversation_key'] );
            return;
        }

        $status = (int) wp_remote_retrieve_response_code( $response );
        if ( $status < 200 || $status >= 300 ) {
            self::log_error( 'manychat_http_' . $status, $payload['conversation_key'] );
        }
    }

    private static function get_state( string $conversation_key ): string {
        return 'human_active' === get_transient( self::state_key( $conversation_key ) ) ? 'human_active' : 'ai_active';
    }

    private static function state_key( string $conversation_key ): string {
        return 'ishi_social_state_' . hash_hmac( 'sha256', $conversation_key, self::hash_secret() );
    }

    private static function settings(): array {
        $defaults = [
            'bot_id'              => 'default',
            'manychat_api_key'    => '',
            'per_contact_limit'   => 12,
            'global_limit'        => 120,
            'max_reply_instagram' => 950,
            'max_reply_default'   => 1800,
        ];
        $saved = get_option( self::OPTION, [] );
        return wp_parse_args( is_array( $saved ) ? $saved : [], $defaults );
    }

    private static function manychat_api_key(): string {
        if ( defined( 'ISHI_SOCIAL_MANYCHAT_API_KEY' ) && ISHI_SOCIAL_MANYCHAT_API_KEY ) {
            return trim( (string) ISHI_SOCIAL_MANYCHAT_API_KEY );
        }
        return trim( (string) self::settings()['manychat_api_key'] );
    }

    private static function gateway_token_hash(): string {
        if ( defined( 'ISHI_SOCIAL_GATEWAY_TOKEN_HASH' ) && ISHI_SOCIAL_GATEWAY_TOKEN_HASH ) {
            return trim( (string) ISHI_SOCIAL_GATEWAY_TOKEN_HASH );
        }
        return trim( (string) get_option( self::TOKEN_HASH_OPTION, '' ) );
    }

    private static function hash_secret(): string {
        if ( defined( 'AUTH_SALT' ) && AUTH_SALT ) {
            return (string) AUTH_SALT;
        }
        return wp_salt( 'auth' );
    }

    private static function json_response( array $data, int $status = 200 ): WP_REST_Response {
        $response = new WP_REST_Response( $data, $status );
        $response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
        return $response;
    }

    private static function log_error( string $code, string $conversation_key ): void {
        $contact_hash = substr( hash_hmac( 'sha256', $conversation_key, self::hash_secret() ), 0, 12 );
        error_log( sprintf( '[Ishi Social AI] %s contact=%s', sanitize_key( $code ), $contact_hash ) );
    }

    public static function admin_menu(): void {
        add_options_page(
            'Ishi Social AI Gateway',
            'Ishi Social AI Gateway',
            'manage_options',
            'ishi-social-ai-gateway',
            [ __CLASS__, 'settings_page' ]
        );
    }

    public static function register_settings(): void {
        register_setting(
            'ishi_social_ai_gateway',
            self::OPTION,
            [
                'type'              => 'array',
                'sanitize_callback' => [ __CLASS__, 'sanitize_settings' ],
                'default'           => [],
            ]
        );
    }

    public static function sanitize_settings( $input ): array {
        $current = self::settings();
        $input   = is_array( $input ) ? $input : [];

        $api_key = isset( $input['manychat_api_key'] ) ? trim( (string) $input['manychat_api_key'] ) : '';
        if ( '' === $api_key ) {
            $api_key = $current['manychat_api_key'];
        }

        return [
            'bot_id'              => sanitize_text_field( (string) ( $input['bot_id'] ?? 'default' ) ),
            'manychat_api_key'    => $api_key,
            'per_contact_limit'   => min( 60, max( 1, (int) ( $input['per_contact_limit'] ?? 12 ) ) ),
            'global_limit'        => min( 1000, max( 10, (int) ( $input['global_limit'] ?? 120 ) ) ),
            'max_reply_instagram' => min( 1000, max( 200, (int) ( $input['max_reply_instagram'] ?? 950 ) ) ),
            'max_reply_default'   => min( 2000, max( 200, (int) ( $input['max_reply_default'] ?? 1800 ) ) ),
        ];
    }

    public static function rotate_token(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized.' );
        }
        check_admin_referer( 'ishi_social_ai_rotate_token' );

        $token = 'ishi_' . wp_generate_password( 48, false, false );
        update_option( self::TOKEN_HASH_OPTION, hash( 'sha256', $token ), false );
        set_transient( self::TOKEN_NOTICE_PREFIX . get_current_user_id(), $token, 5 * MINUTE_IN_SECONDS );

        wp_safe_redirect( admin_url( 'options-general.php?page=ishi-social-ai-gateway&token_rotated=1' ) );
        exit;
    }

    public static function settings_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $settings = self::settings();
        $new_token = get_transient( self::TOKEN_NOTICE_PREFIX . get_current_user_id() );
        if ( $new_token ) {
            delete_transient( self::TOKEN_NOTICE_PREFIX . get_current_user_id() );
        }
        ?>
        <div class="wrap">
            <h1>Ishi Social AI Gateway</h1>
            <p>Secure asynchronous bridge between ManyChat and the existing AI Engine chatbot.</p>

            <?php if ( $new_token ) : ?>
                <div class="notice notice-success"><p><strong>New gateway token — copy it now. It will not be shown again:</strong></p>
                    <p><code style="font-size:14px;user-select:all;"><?php echo esc_html( $new_token ); ?></code></p>
                </div>
            <?php endif; ?>

            <table class="widefat striped" style="max-width:900px;margin:20px 0;">
                <tbody>
                    <tr><td><strong>Inbound endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/message' ) ); ?></code></td></tr>
                    <tr><td><strong>State endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/state' ) ); ?></code></td></tr>
                    <tr><td><strong>Health endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/health' ) ); ?></code></td></tr>
                    <tr><td><strong>Gateway token configured</strong></td><td><?php echo self::gateway_token_hash() ? 'Yes' : 'No'; ?></td></tr>
                    <tr><td><strong>Queue backend</strong></td><td><?php echo function_exists( 'as_enqueue_async_action' ) ? 'Action Scheduler' : 'WP-Cron fallback'; ?></td></tr>
                </tbody>
            </table>

            <form method="post" action="options.php">
                <?php settings_fields( 'ishi_social_ai_gateway' ); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ishi-bot-id">AI Engine chatbot ID</label></th>
                        <td><input id="ishi-bot-id" class="regular-text" name="<?php echo esc_attr( self::OPTION ); ?>[bot_id]" value="<?php echo esc_attr( $settings['bot_id'] ); ?>"><p class="description">Usually <code>default</code> unless your Ishi chatbot uses another Bot ID.</p></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ishi-manychat-key">ManyChat Account Public API key</label></th>
                        <td><input id="ishi-manychat-key" type="password" autocomplete="new-password" class="regular-text" name="<?php echo esc_attr( self::OPTION ); ?>[manychat_api_key]" value="" placeholder="Leave blank to keep the existing key"><p class="description">Recommended: define <code>ISHI_SOCIAL_MANYCHAT_API_KEY</code> in wp-config.php instead of storing it in WordPress.</p></td>
                    </tr>
                    <tr>
                        <th scope="row">Per-contact requests/minute</th>
                        <td><input type="number" min="1" max="60" name="<?php echo esc_attr( self::OPTION ); ?>[per_contact_limit]" value="<?php echo esc_attr( $settings['per_contact_limit'] ); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row">Global inbound requests/minute</th>
                        <td><input type="number" min="10" max="1000" name="<?php echo esc_attr( self::OPTION ); ?>[global_limit]" value="<?php echo esc_attr( $settings['global_limit'] ); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row">Instagram reply character cap</th>
                        <td><input type="number" min="200" max="1000" name="<?php echo esc_attr( self::OPTION ); ?>[max_reply_instagram]" value="<?php echo esc_attr( $settings['max_reply_instagram'] ); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row">Other channel reply character cap</th>
                        <td><input type="number" min="200" max="2000" name="<?php echo esc_attr( self::OPTION ); ?>[max_reply_default]" value="<?php echo esc_attr( $settings['max_reply_default'] ); ?>"></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <hr>
            <h2>Gateway authentication token</h2>
            <p>ManyChat should send this as <code>Authorization: Bearer &lt;token&gt;</code>. Only a SHA-256 hash is stored by the plugin.</p>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <input type="hidden" name="action" value="ishi_social_ai_rotate_token">
                <?php wp_nonce_field( 'ishi_social_ai_rotate_token' ); ?>
                <?php submit_button( self::gateway_token_hash() ? 'Rotate Gateway Token' : 'Generate Gateway Token', 'secondary' ); ?>
            </form>
        </div>
        <?php
    }
}

register_activation_hook( __FILE__, [ Gateway::class, 'activate' ] );
Gateway::boot();
