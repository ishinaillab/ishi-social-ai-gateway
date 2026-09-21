<?php
/**
 * Plugin Name: Ishi Social AI Gateway
 * Description: Secure social-channel gateway for Ishi Nail Lab. Preserves the legacy asynchronous ManyChat bridge and adds a synchronous Chatfuel transport endpoint for the existing AI Engine chatbot.
 * Version: 1.1.0
 * Author: Ishi Nail Lab
 * Requires at least: 6.9
 * Requires PHP: 8.1
 */

namespace Ishi\SocialAI;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class Gateway {
    private const VERSION = '1.1.0';
    private const SCHEMA_VERSION = '1.1.0';

    private const OPTION = 'ishi_social_ai_gateway_settings';
    private const SCHEMA_OPTION = 'ishi_social_ai_gateway_schema_version';
    private const CHAT_ID_SECRET_OPTION = 'ishi_social_ai_chat_id_secret';

    /** Legacy ManyChat / management credential. */
    private const TOKEN_HASH_OPTION = 'ishi_social_ai_gateway_token_hash';
    private const TOKEN_NOTICE_PREFIX = 'ishi_social_ai_gateway_token_notice_';

    /** Dedicated Chatfuel bridge -> WordPress credential. */
    private const CHATFUEL_TOKEN_HASH_OPTION = 'ishi_social_ai_chatfuel_token_hash';
    private const CHATFUEL_TOKEN_NOTICE_PREFIX = 'ishi_social_ai_chatfuel_token_notice_';

    private const REST_NS = 'ishi-social-ai/v1';
    private const PROCESS_HOOK = 'ishi_social_ai_process_message';

    private const MAX_MESSAGE_CHARS = 4000;
    private const MAX_IDENTIFIER_CHARS = 255;
    private const IDEMPOTENCY_TTL = DAY_IN_SECONDS;
    private const PROCESSING_STALE_AFTER = 5 * MINUTE_IN_SECONDS;
    private const FALLBACK_DEDUPE_TTL = 15;
    private const HANDOFF_TTL = 7 * DAY_IN_SECONDS;
    private const CLEANUP_INTERVAL = HOUR_IN_SECONDS;

    public static function boot(): void {
        add_action( 'plugins_loaded', [ __CLASS__, 'maybe_upgrade' ], 20 );
        add_action( 'rest_api_init', [ __CLASS__, 'register_routes' ] );
        add_filter( 'rest_post_dispatch', [ __CLASS__, 'add_no_store_headers' ], 10, 3 );

        add_action( 'admin_menu', [ __CLASS__, 'admin_menu' ] );
        add_action( 'admin_init', [ __CLASS__, 'register_settings' ] );
        add_action( 'admin_post_ishi_social_ai_rotate_token', [ __CLASS__, 'rotate_token' ] );
        add_action( 'admin_post_ishi_social_ai_rotate_chatfuel_token', [ __CLASS__, 'rotate_chatfuel_token' ] );

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

        self::ensure_chat_id_secret();
        self::install_schema();
    }

    public static function maybe_upgrade(): void {
        if ( self::SCHEMA_VERSION !== (string) get_option( self::SCHEMA_OPTION, '' ) ) {
            self::ensure_chat_id_secret();
            self::install_schema();
        }
    }

    private static function install_schema(): void {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset_collate = $wpdb->get_charset_collate();
        $requests = self::requests_table();
        $states   = self::states_table();
        $rates    = self::rates_table();

        dbDelta(
            "CREATE TABLE {$requests} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                channel varchar(32) NOT NULL,
                message_hash char(64) NOT NULL,
                contact_hash char(64) NOT NULL,
                status varchar(20) NOT NULL,
                response_json longtext NULL,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                expires_at datetime NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY channel_message (channel, message_hash),
                KEY expires_at (expires_at),
                KEY contact_hash (contact_hash)
            ) {$charset_collate};"
        );

        dbDelta(
            "CREATE TABLE {$states} (
                conversation_hash char(64) NOT NULL,
                state varchar(20) NOT NULL,
                updated_at datetime NOT NULL,
                expires_at datetime NOT NULL,
                PRIMARY KEY  (conversation_hash),
                KEY expires_at (expires_at)
            ) {$charset_collate};"
        );

        dbDelta(
            "CREATE TABLE {$rates} (
                bucket_hash char(64) NOT NULL,
                hits int(10) unsigned NOT NULL DEFAULT 0,
                expires_at datetime NOT NULL,
                PRIMARY KEY  (bucket_hash),
                KEY expires_at (expires_at)
            ) {$charset_collate};"
        );

        update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
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
            '/respond',
            [
                'methods'             => 'POST',
                'callback'            => [ __CLASS__, 'respond' ],
                'permission_callback' => [ __CLASS__, 'authenticate_chatfuel_request' ],
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
        return self::verify_bearer( $request, self::gateway_token_hash() );
    }

    public static function authenticate_chatfuel_request( WP_REST_Request $request ) {
        return self::verify_bearer( $request, self::chatfuel_token_hash() );
    }

    private static function verify_bearer( WP_REST_Request $request, string $stored_hash ) {
        if ( '' === $stored_hash ) {
            return new WP_Error(
                'ishi_gateway_not_configured',
                'Gateway authentication is not configured.',
                [ 'status' => 503 ]
            );
        }

        $header = trim( (string) $request->get_header( 'authorization' ) );
        if ( ! preg_match( '/^Bearer\s+([^\s]+)$/i', $header, $matches ) ) {
            return new WP_Error( 'ishi_gateway_unauthorized', 'Unauthorized.', [ 'status' => 401 ] );
        }

        $provided_hash = hash( 'sha256', $matches[1] );
        if ( ! hash_equals( $stored_hash, $provided_hash ) ) {
            return new WP_Error( 'ishi_gateway_unauthorized', 'Unauthorized.', [ 'status' => 401 ] );
        }

        return true;
    }

    /**
     * Legacy ManyChat entry point. Its behavior intentionally remains
     * asynchronous because ManyChat's external-request timeout is short.
     */
    public static function receive_message( WP_REST_Request $request ): WP_REST_Response|WP_Error {
        $json = self::json_body( $request );
        if ( is_wp_error( $json ) ) {
            return $json;
        }

        $payload = self::normalize_payload( $json, false );
        if ( is_wp_error( $payload ) ) {
            return $payload;
        }

        $rate = self::check_rate_limits( $payload['conversation_key'] );
        if ( is_wp_error( $rate ) ) {
            return $rate;
        }

        if ( 'ai_active' !== self::get_state( $payload['conversation_key'] ) ) {
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

        set_transient(
            $dedupe_key,
            1,
            ! empty( $payload['message_id'] ) ? self::IDEMPOTENCY_TTL : self::FALLBACK_DEDUPE_TTL
        );

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

    /**
     * Synchronous Chatfuel bridge endpoint.
     *
     * One inbound Chatfuel message can result in at most one paid AI turn.
     * Idempotency is claimed before rate limiting and before AI Engine.
     */
    public static function respond( WP_REST_Request $request ): WP_REST_Response|WP_Error {
        $json = self::json_body( $request );
        if ( is_wp_error( $json ) ) {
            return $json;
        }

        $payload = self::normalize_payload( $json, true );
        if ( is_wp_error( $payload ) ) {
            return $payload;
        }

        if ( 'instagram' !== $payload['channel'] ) {
            return new WP_Error( 'ishi_gateway_invalid_channel', 'Unsupported channel.', [ 'status' => 400 ] );
        }

        self::maybe_cleanup_storage();

        $claim = self::claim_request( $payload );
        if ( is_wp_error( $claim ) ) {
            return $claim;
        }

        if ( is_array( $claim ) && isset( $claim['cached_response'] ) ) {
            return self::json_response( $claim['cached_response'] );
        }

        if ( 'ai_active' !== self::get_state( $payload['conversation_key'] ) ) {
            $response = [ 'ok' => true, 'reply' => '', 'handoff' => true ];
            self::complete_request( $payload, $response );
            return self::json_response( $response );
        }

        $rate = self::check_rate_limits( $payload['conversation_key'] );
        if ( is_wp_error( $rate ) ) {
            self::release_request( $payload );
            return $rate;
        }

        $context = self::trusted_context( $payload, true );
        $reply = self::query_ai_engine( $payload, $context, true );

        if ( is_wp_error( $reply ) ) {
            self::fail_request( $payload );
            return $reply;
        }

        $reply = self::limit_reply( $reply, $payload['channel'] );

        /**
         * Extension point for a deterministic handoff policy. The default is
         * false; free-form AI text is never parsed for magic handoff phrases.
         */
        $handoff = (bool) apply_filters( 'ishi_social_ai_handoff_required', false, $payload, $reply );

        if ( $handoff ) {
            self::set_state( $payload['conversation_key'], 'human_required' );
            $response = [ 'ok' => true, 'reply' => '', 'handoff' => true ];
        } else {
            $response = [ 'ok' => true, 'reply' => $reply, 'handoff' => false ];
        }

        self::complete_request( $payload, $response );
        return self::json_response( $response );
    }

    public static function process_queued_message( string $job_id ): void {
        $key     = 'ishi_social_job_' . md5( $job_id );
        $payload = get_transient( $key );
        delete_transient( $key );

        if ( ! is_array( $payload ) ) {
            return;
        }

        if ( 'ai_active' !== self::get_state( $payload['conversation_key'] ) ) {
            return;
        }

        $reply = self::query_ai_engine( $payload, self::trusted_context( $payload, false ), false );
        if ( is_wp_error( $reply ) ) {
            self::log_error( $reply->get_error_code(), $payload['conversation_key'] );
            return;
        }

        $reply = self::limit_reply( $reply, $payload['channel'] );
        self::send_manychat_reply( $payload, $reply );
    }

    private static function query_ai_engine( array $payload, string $context, bool $chatfuel ): string|WP_Error {
        global $mwai;

        if ( ! is_object( $mwai ) || ! method_exists( $mwai, 'simpleChatbotQuery' ) ) {
            self::log_error( 'ai_engine_unavailable', $payload['conversation_key'] );
            return new WP_Error(
                'ishi_gateway_ai_unavailable',
                'AI service is temporarily unavailable.',
                [ 'status' => 503 ]
            );
        }

        $bot_id = self::settings()['bot_id'] ?: 'default';
        $chat_id = self::chat_id( $payload['conversation_key'], $chatfuel );

        $instruction_filter = static function ( $instructions, $query ) use ( $context ) {
            return rtrim( (string) $instructions ) . "\n\n" . $context;
        };

        add_filter( 'mwai_ai_instructions', $instruction_filter, 999, 2 );

        try {
            /*
             * AI Engine's current PHP API supports:
             * simpleChatbotQuery( $botId, $message, $params = [], $onlyReply = true )
             * A stable chatId lets AI Engine load/persist the configured chatbot
             * discussion while retaining its normal Knowledge/MCP/tool pipeline.
             */
            $reply = $mwai->simpleChatbotQuery(
                $bot_id,
                $payload['message'],
                [ 'chatId' => $chat_id ],
                true
            );
        } catch ( \Throwable $e ) {
            self::log_error( 'ai_query_failed', $payload['conversation_key'] );
            return new WP_Error(
                'ishi_gateway_ai_failed',
                'AI service is temporarily unavailable.',
                [ 'status' => 502 ]
            );
        } finally {
            remove_filter( 'mwai_ai_instructions', $instruction_filter, 999 );
        }

        $reply = self::extract_reply_text( $reply );
        if ( '' === $reply ) {
            self::log_error( 'empty_ai_reply', $payload['conversation_key'] );
            return new WP_Error(
                'ishi_gateway_empty_ai_reply',
                'AI service returned no reply.',
                [ 'status' => 502 ]
            );
        }

        return $reply;
    }

    public static function set_conversation_state( WP_REST_Request $request ): WP_REST_Response|WP_Error {
        $json = self::json_body( $request );
        if ( is_wp_error( $json ) ) {
            return $json;
        }

        $channel = self::normalize_channel( $json['channel'] ?? '' );
        $contact_id = self::normalize_identifier( $json['contact_id'] ?? '' );
        $state = sanitize_key( (string) ( $json['state'] ?? '' ) );

        if ( ! $channel || is_wp_error( $contact_id ) ) {
            return new WP_Error(
                'ishi_gateway_invalid_state_request',
                'channel and contact_id are required.',
                [ 'status' => 400 ]
            );
        }

        if ( ! in_array( $state, [ 'ai_active', 'human_required', 'human_active' ], true ) ) {
            return new WP_Error(
                'ishi_gateway_invalid_state',
                'state must be ai_active, human_required, or human_active.',
                [ 'status' => 400 ]
            );
        }

        self::set_state( $channel . ':' . $contact_id, $state );
        return self::json_response( [ 'ok' => true, 'state' => $state ] );
    }

    public static function health( WP_REST_Request $request ): WP_REST_Response {
        return self::json_response(
            [
                'ok'                   => true,
                'version'              => self::VERSION,
                'schema_version'       => (string) get_option( self::SCHEMA_OPTION, '' ),
                'ai_engine_ready'      => self::ai_engine_ready(),
                'gateway_token_ready'  => '' !== self::gateway_token_hash(),
                'chatfuel_token_ready' => '' !== self::chatfuel_token_hash(),
                'manychat_key_ready'   => '' !== self::manychat_api_key(),
                'queue'                => function_exists( 'as_enqueue_async_action' ) ? 'action_scheduler' : 'wp_cron',
            ]
        );
    }

    public static function add_no_store_headers( $response, $server, WP_REST_Request $request ) {
        $route = (string) $request->get_route();
        if ( 0 === strpos( $route, '/' . self::REST_NS . '/' ) && $response instanceof WP_REST_Response ) {
            $response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
            $response->header( 'Pragma', 'no-cache' );

            if ( 429 === $response->get_status() ) {
                $response->header( 'Retry-After', '60' );
            } elseif ( 409 === $response->get_status() ) {
                $response->header( 'Retry-After', '2' );
            }
        }
        return $response;
    }

    private static function json_body( WP_REST_Request $request ): array|WP_Error {
        $content_type = strtolower( trim( (string) $request->get_header( 'content-type' ) ) );
        if ( ! preg_match( '#^application/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)#i', $content_type ) ) {
            return new WP_Error(
                'ishi_gateway_content_type',
                'Content-Type must be application/json.',
                [ 'status' => 415 ]
            );
        }

        if ( method_exists( $request, 'get_json_error' ) ) {
            $json_error = $request->get_json_error();
            if ( is_wp_error( $json_error ) ) {
                return new WP_Error( 'ishi_gateway_invalid_json', 'Invalid JSON body.', [ 'status' => 400 ] );
            }
        }

        $data = $request->get_json_params();
        if ( ! is_array( $data ) ) {
            return new WP_Error( 'ishi_gateway_invalid_json', 'JSON body must be an object.', [ 'status' => 400 ] );
        }

        return $data;
    }

    private static function normalize_payload( array $data, bool $require_message_id ) {
        $channel = self::normalize_channel( $data['channel'] ?? '' );
        if ( ! $channel ) {
            return new WP_Error( 'ishi_gateway_invalid_channel', 'Unsupported channel.', [ 'status' => 400 ] );
        }

        $contact_id = self::normalize_identifier( $data['contact_id'] ?? '' );
        if ( is_wp_error( $contact_id ) ) {
            return $contact_id;
        }

        $message_id = '';
        if ( isset( $data['message_id'] ) && '' !== trim( (string) $data['message_id'] ) ) {
            $normalized_message_id = self::normalize_identifier( $data['message_id'] );
            if ( is_wp_error( $normalized_message_id ) ) {
                return new WP_Error( 'ishi_gateway_invalid_message_id', 'Invalid message_id.', [ 'status' => 400 ] );
            }
            $message_id = $normalized_message_id;
        } elseif ( $require_message_id ) {
            return new WP_Error( 'ishi_gateway_missing_message_id', 'message_id is required.', [ 'status' => 400 ] );
        }

        $message = sanitize_textarea_field( (string) ( $data['message'] ?? '' ) );
        $message = trim( $message );
        if ( '' === $message ) {
            return new WP_Error( 'ishi_gateway_missing_fields', 'contact_id and message are required.', [ 'status' => 400 ] );
        }

        $message_length = function_exists( 'mb_strlen' ) ? mb_strlen( $message ) : strlen( $message );
        if ( $message_length > self::MAX_MESSAGE_CHARS ) {
            return new WP_Error( 'ishi_gateway_message_too_long', 'Message is too long.', [ 'status' => 413 ] );
        }

        $first_name = sanitize_text_field( (string) ( $data['first_name'] ?? '' ) );
        $language   = sanitize_text_field( (string) ( $data['language'] ?? '' ) );

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

    private static function normalize_identifier( $value ): string|WP_Error {
        if ( ! is_scalar( $value ) ) {
            return new WP_Error( 'ishi_gateway_invalid_identifier', 'Invalid identifier.', [ 'status' => 400 ] );
        }

        $value = trim( (string) $value );
        $length = strlen( $value );

        if ( 0 === $length || $length > self::MAX_IDENTIFIER_CHARS ) {
            return new WP_Error( 'ishi_gateway_invalid_identifier', 'Invalid identifier.', [ 'status' => 400 ] );
        }

        /*
         * Chatfuel identifiers are opaque transport values. Preserve them
         * byte-for-byte, but reject whitespace/control characters and non-ASCII
         * bytes so they cannot become ambiguous protocol/log input.
         */
        if ( ! preg_match( '/\A[\x21-\x7E]+\z/D', $value ) ) {
            return new WP_Error( 'ishi_gateway_invalid_identifier', 'Invalid identifier.', [ 'status' => 400 ] );
        }

        return $value;
    }

    private static function normalize_channel( $channel ): string {
        $channel = strtolower( sanitize_key( (string) $channel ) );
        $aliases = [ 'facebook' => 'messenger', 'fb' => 'messenger', 'ig' => 'instagram' ];
        $channel = $aliases[ $channel ] ?? $channel;

        return in_array( $channel, [ 'instagram', 'messenger', 'whatsapp', 'telegram' ], true ) ? $channel : '';
    }

    private static function claim_request( array $payload ): array|bool|WP_Error {
        global $wpdb;

        $table = self::requests_table();
        $channel = $payload['channel'];
        $message_hash = self::message_hash( $payload );
        $contact_hash = self::conversation_hash( $payload['conversation_key'] );
        $now = current_time( 'mysql', true );
        $expires = gmdate( 'Y-m-d H:i:s', time() + self::IDEMPOTENCY_TTL );

        $inserted = $wpdb->query(
            $wpdb->prepare(
                "INSERT IGNORE INTO {$table}
                    (channel, message_hash, contact_hash, status, response_json, created_at, updated_at, expires_at)
                 VALUES (%s, %s, %s, 'processing', NULL, %s, %s, %s)",
                $channel,
                $message_hash,
                $contact_hash,
                $now,
                $now,
                $expires
            )
        );

        if ( 1 === $inserted ) {
            return true;
        }

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT status, response_json, updated_at, expires_at
                 FROM {$table}
                 WHERE channel = %s AND message_hash = %s
                 LIMIT 1",
                $channel,
                $message_hash
            ),
            ARRAY_A
        );

        if ( ! is_array( $row ) ) {
            return new WP_Error(
                'ishi_gateway_idempotency_failed',
                'Request could not be safely processed.',
                [ 'status' => 503 ]
            );
        }

        if ( strtotime( (string) $row['expires_at'] . ' UTC' ) <= time() ) {
            $wpdb->delete( $table, [ 'channel' => $channel, 'message_hash' => $message_hash ], [ '%s', '%s' ] );
            return self::claim_request( $payload );
        }

        if ( 'completed' === $row['status'] && ! empty( $row['response_json'] ) ) {
            $cached = json_decode( (string) $row['response_json'], true );
            if ( is_array( $cached ) ) {
                return [ 'cached_response' => $cached ];
            }
        }

        if ( 'failed' === $row['status'] ) {
            $updated = $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$table}
                     SET status = 'processing', response_json = NULL, updated_at = %s, expires_at = %s
                     WHERE channel = %s AND message_hash = %s AND status = 'failed'",
                    $now,
                    $expires,
                    $channel,
                    $message_hash
                )
            );
            if ( 1 === $updated ) {
                return true;
            }
        }

        $updated_at = strtotime( (string) $row['updated_at'] . ' UTC' );
        if ( 'processing' === $row['status'] && $updated_at && $updated_at < ( time() - self::PROCESSING_STALE_AFTER ) ) {
            $stale_before = gmdate( 'Y-m-d H:i:s', time() - self::PROCESSING_STALE_AFTER );
            $updated = $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$table}
                     SET updated_at = %s, expires_at = %s
                     WHERE channel = %s
                       AND message_hash = %s
                       AND status = 'processing'
                       AND updated_at < %s",
                    $now,
                    $expires,
                    $channel,
                    $message_hash,
                    $stale_before
                )
            );
            if ( 1 === $updated ) {
                return true;
            }
        }

        return new WP_Error(
            'ishi_gateway_request_in_progress',
            'This message is already being processed.',
            [ 'status' => 409, 'retry_after' => 2 ]
        );
    }

    private static function complete_request( array $payload, array $response ): void {
        global $wpdb;

        $wpdb->update(
            self::requests_table(),
            [
                'status'        => 'completed',
                'response_json' => wp_json_encode( $response ),
                'updated_at'    => current_time( 'mysql', true ),
            ],
            [
                'channel'      => $payload['channel'],
                'message_hash' => self::message_hash( $payload ),
            ],
            [ '%s', '%s', '%s' ],
            [ '%s', '%s' ]
        );
    }

    private static function fail_request( array $payload ): void {
        global $wpdb;

        $wpdb->update(
            self::requests_table(),
            [
                'status'     => 'failed',
                'updated_at' => current_time( 'mysql', true ),
            ],
            [
                'channel'      => $payload['channel'],
                'message_hash' => self::message_hash( $payload ),
            ],
            [ '%s', '%s' ],
            [ '%s', '%s' ]
        );
    }

    private static function release_request( array $payload ): void {
        global $wpdb;

        $wpdb->delete(
            self::requests_table(),
            [
                'channel'      => $payload['channel'],
                'message_hash' => self::message_hash( $payload ),
            ],
            [ '%s', '%s' ]
        );
    }

    private static function check_rate_limits( string $conversation_key ) {
        $settings = self::settings();
        $per_contact_limit = max( 1, (int) $settings['per_contact_limit'] );
        $global_limit      = max( 1, (int) $settings['global_limit'] );

        $minute = gmdate( 'YmdHi' );
        $contact_bucket = self::opaque_hash( 'rate:contact:' . $conversation_key . ':' . $minute );
        $global_bucket  = self::opaque_hash( 'rate:global:' . $minute );

        $contact_count = self::increment_rate_bucket( $contact_bucket );
        $global_count  = self::increment_rate_bucket( $global_bucket );

        if ( false === $contact_count || false === $global_count ) {
            return new WP_Error(
                'ishi_gateway_rate_storage_failed',
                'Request could not be safely processed.',
                [ 'status' => 503 ]
            );
        }

        if ( $contact_count > $per_contact_limit || $global_count > $global_limit ) {
            return new WP_Error(
                'ishi_gateway_rate_limited',
                'Too many requests.',
                [ 'status' => 429, 'retry_after' => 60 ]
            );
        }

        return true;
    }

    private static function increment_rate_bucket( string $bucket_hash ): int|false {
        global $wpdb;

        $table = self::rates_table();
        $expires = gmdate( 'Y-m-d H:i:s', time() + 2 * MINUTE_IN_SECONDS );

        $result = $wpdb->query(
            $wpdb->prepare(
                "INSERT INTO {$table} (bucket_hash, hits, expires_at)
                 VALUES (%s, 1, %s)
                 ON DUPLICATE KEY UPDATE hits = hits + 1, expires_at = VALUES(expires_at)",
                $bucket_hash,
                $expires
            )
        );

        if ( false === $result ) {
            return false;
        }

        $hits = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT hits FROM {$table} WHERE bucket_hash = %s LIMIT 1",
                $bucket_hash
            )
        );

        return null === $hits ? false : (int) $hits;
    }

    private static function dedupe_key( array $payload ): string {
        if ( '' !== $payload['message_id'] ) {
            $fingerprint = 'id|' . $payload['channel'] . '|' . $payload['message_id'];
        } else {
            $fingerprint = 'fallback|' . $payload['conversation_key'] . '|' . $payload['message'];
        }
        return 'ishi_social_dedupe_' . hash( 'sha256', $fingerprint );
    }

    private static function message_hash( array $payload ): string {
        return self::opaque_hash( 'message:' . $payload['channel'] . ':' . $payload['message_id'] );
    }

    private static function conversation_hash( string $conversation_key ): string {
        return self::opaque_hash( 'conversation:' . $conversation_key );
    }

    private static function chat_id( string $conversation_key, bool $chatfuel ): string {
        /*
         * Preserve v1.0 ManyChat discussion continuity exactly. Chatfuel is a
         * new transport in v1.1, so it uses the plugin-owned secret and a
         * domain-separated input from day one.
         */
        if ( ! $chatfuel ) {
            return 'ishi_social_' . substr(
                hash_hmac( 'sha256', $conversation_key, self::legacy_hash_secret() ),
                0,
                40
            );
        }

        return 'ishi_social_' . substr( self::opaque_hash( 'chatfuel-chat:' . $conversation_key ), 0, 40 );
    }

    private static function opaque_hash( string $value ): string {
        return hash_hmac( 'sha256', $value, self::chat_id_secret() );
    }

    private static function trusted_context( array $payload, bool $chatfuel ): string {
        $parts = [
            '## Trusted social-channel context',
            'This metadata is supplied by the Ishi server, not by the customer. Do not reveal internal identifiers or infrastructure details.',
            'Channel: ' . $payload['channel'],
            'Transport: ' . ( $chatfuel ? 'Chatfuel' : 'ManyChat' ),
        ];

        if ( ! $chatfuel && '' !== $payload['first_name'] ) {
            $parts[] = 'Customer first name: ' . $payload['first_name'];
        }
        if ( ! $chatfuel && '' !== $payload['language'] ) {
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
        global $wpdb;

        $hash = self::conversation_hash( $conversation_key );
        $row = $wpdb->get_row(
            $wpdb->prepare(
                'SELECT state, expires_at FROM ' . self::states_table() . ' WHERE conversation_hash = %s LIMIT 1',
                $hash
            ),
            ARRAY_A
        );

        if ( is_array( $row ) ) {
            if ( strtotime( (string) $row['expires_at'] . ' UTC' ) > time() ) {
                return in_array( $row['state'], [ 'human_required', 'human_active' ], true )
                    ? $row['state']
                    : 'ai_active';
            }

            $wpdb->delete( self::states_table(), [ 'conversation_hash' => $hash ], [ '%s' ] );
        }

        /*
         * Backward compatibility for v1.0 transient handoff state. It can be
         * removed naturally after its original TTL expires.
         */
        $legacy_key = 'ishi_social_state_' . hash_hmac( 'sha256', $conversation_key, self::legacy_hash_secret() );
        return 'human_active' === get_transient( $legacy_key ) ? 'human_active' : 'ai_active';
    }

    private static function set_state( string $conversation_key, string $state ): void {
        global $wpdb;

        $hash = self::conversation_hash( $conversation_key );

        if ( 'ai_active' === $state ) {
            $wpdb->delete( self::states_table(), [ 'conversation_hash' => $hash ], [ '%s' ] );
            $legacy_key = 'ishi_social_state_' . hash_hmac( 'sha256', $conversation_key, self::legacy_hash_secret() );
            delete_transient( $legacy_key );
            return;
        }

        $now = current_time( 'mysql', true );
        $expires = gmdate( 'Y-m-d H:i:s', time() + self::HANDOFF_TTL );

        $wpdb->query(
            $wpdb->prepare(
                'INSERT INTO ' . self::states_table() . ' (conversation_hash, state, updated_at, expires_at)
                 VALUES (%s, %s, %s, %s)
                 ON DUPLICATE KEY UPDATE state = VALUES(state), updated_at = VALUES(updated_at), expires_at = VALUES(expires_at)',
                $hash,
                $state,
                $now,
                $expires
            )
        );
    }

    private static function maybe_cleanup_storage(): void {
        if ( get_transient( 'ishi_social_ai_cleanup_lock' ) ) {
            return;
        }

        set_transient( 'ishi_social_ai_cleanup_lock', 1, self::CLEANUP_INTERVAL );

        global $wpdb;
        $now = current_time( 'mysql', true );

        $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::requests_table() . ' WHERE expires_at < %s', $now ) );
        $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::states_table() . ' WHERE expires_at < %s', $now ) );
        $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::rates_table() . ' WHERE expires_at < %s', $now ) );
    }

    private static function requests_table(): string {
        global $wpdb;
        return $wpdb->prefix . 'ishi_social_ai_requests';
    }

    private static function states_table(): string {
        global $wpdb;
        return $wpdb->prefix . 'ishi_social_ai_states';
    }

    private static function rates_table(): string {
        global $wpdb;
        return $wpdb->prefix . 'ishi_social_ai_rates';
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

    private static function chatfuel_token_hash(): string {
        if ( defined( 'ISHI_SOCIAL_CHATFUEL_TOKEN_HASH' ) && ISHI_SOCIAL_CHATFUEL_TOKEN_HASH ) {
            return trim( (string) ISHI_SOCIAL_CHATFUEL_TOKEN_HASH );
        }
        return trim( (string) get_option( self::CHATFUEL_TOKEN_HASH_OPTION, '' ) );
    }

    private static function ensure_chat_id_secret(): void {
        if ( false === get_option( self::CHAT_ID_SECRET_OPTION, false ) ) {
            add_option(
                self::CHAT_ID_SECRET_OPTION,
                wp_generate_password( 64, true, true ),
                '',
                false
            );
        }
    }

    private static function chat_id_secret(): string {
        if ( defined( 'ISHI_SOCIAL_CHAT_ID_SECRET' ) && ISHI_SOCIAL_CHAT_ID_SECRET ) {
            return (string) ISHI_SOCIAL_CHAT_ID_SECRET;
        }

        $secret = (string) get_option( self::CHAT_ID_SECRET_OPTION, '' );
        if ( '' === $secret ) {
            self::ensure_chat_id_secret();
            $secret = (string) get_option( self::CHAT_ID_SECRET_OPTION, '' );
        }

        return '' !== $secret ? $secret : self::legacy_hash_secret();
    }

    private static function legacy_hash_secret(): string {
        if ( defined( 'AUTH_SALT' ) && AUTH_SALT ) {
            return (string) AUTH_SALT;
        }
        return wp_salt( 'auth' );
    }

    private static function ai_engine_ready(): bool {
        global $mwai;
        return is_object( $mwai ) && method_exists( $mwai, 'simpleChatbotQuery' );
    }

    private static function json_response( array $data, int $status = 200 ): WP_REST_Response {
        $response = new WP_REST_Response( $data, $status );
        $response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
        $response->header( 'Pragma', 'no-cache' );
        return $response;
    }

    private static function log_error( string $code, string $conversation_key ): void {
        $contact_hash = substr( self::conversation_hash( $conversation_key ), 0, 12 );
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

    public static function rotate_chatfuel_token(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized.' );
        }

        check_admin_referer( 'ishi_social_ai_rotate_chatfuel_token' );

        $token = 'ishi_cf_' . wp_generate_password( 48, false, false );
        update_option( self::CHATFUEL_TOKEN_HASH_OPTION, hash( 'sha256', $token ), false );
        set_transient(
            self::CHATFUEL_TOKEN_NOTICE_PREFIX . get_current_user_id(),
            $token,
            5 * MINUTE_IN_SECONDS
        );

        wp_safe_redirect( admin_url( 'options-general.php?page=ishi-social-ai-gateway&chatfuel_token_rotated=1' ) );
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

        $new_chatfuel_token = get_transient( self::CHATFUEL_TOKEN_NOTICE_PREFIX . get_current_user_id() );
        if ( $new_chatfuel_token ) {
            delete_transient( self::CHATFUEL_TOKEN_NOTICE_PREFIX . get_current_user_id() );
        }
        ?>
        <div class="wrap">
            <h1>Ishi Social AI Gateway</h1>
            <p>Secure transport layer for the existing Ishi AI Engine chatbot. Chatfuel uses the synchronous endpoint; the legacy ManyChat bridge remains asynchronous.</p>

            <?php if ( $new_token ) : ?>
                <div class="notice notice-success"><p><strong>New legacy gateway token — copy it now. It will not be shown again:</strong></p>
                    <p><code style="font-size:14px;user-select:all;"><?php echo esc_html( $new_token ); ?></code></p>
                </div>
            <?php endif; ?>

            <?php if ( $new_chatfuel_token ) : ?>
                <div class="notice notice-success"><p><strong>New Chatfuel bridge token — copy it now. It will not be shown again:</strong></p>
                    <p><code style="font-size:14px;user-select:all;"><?php echo esc_html( $new_chatfuel_token ); ?></code></p>
                </div>
            <?php endif; ?>

            <table class="widefat striped" style="max-width:980px;margin:20px 0;">
                <tbody>
                    <tr><td><strong>Chatfuel synchronous endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/respond' ) ); ?></code></td></tr>
                    <tr><td><strong>Legacy ManyChat endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/message' ) ); ?></code></td></tr>
                    <tr><td><strong>State endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/state' ) ); ?></code></td></tr>
                    <tr><td><strong>Health endpoint</strong></td><td><code><?php echo esc_html( rest_url( self::REST_NS . '/health' ) ); ?></code></td></tr>
                    <tr><td><strong>Chatfuel token configured</strong></td><td><?php echo self::chatfuel_token_hash() ? 'Yes' : 'No'; ?></td></tr>
                    <tr><td><strong>Legacy gateway token configured</strong></td><td><?php echo self::gateway_token_hash() ? 'Yes' : 'No'; ?></td></tr>
                    <tr><td><strong>AI Engine PHP API ready</strong></td><td><?php echo self::ai_engine_ready() ? 'Yes' : 'No'; ?></td></tr>
                    <tr><td><strong>Storage schema</strong></td><td><code><?php echo esc_html( (string) get_option( self::SCHEMA_OPTION, 'not installed' ) ); ?></code></td></tr>
                    <tr><td><strong>Queue backend</strong></td><td><?php echo function_exists( 'as_enqueue_async_action' ) ? 'Action Scheduler' : 'WP-Cron fallback'; ?></td></tr>
                </tbody>
            </table>

            <form method="post" action="options.php">
                <?php settings_fields( 'ishi_social_ai_gateway' ); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ishi-bot-id">AI Engine chatbot ID</label></th>
                        <td><input id="ishi-bot-id" class="regular-text" name="<?php echo esc_attr( self::OPTION ); ?>[bot_id]" value="<?php echo esc_attr( $settings['bot_id'] ); ?>"><p class="description">Use the exact Bot ID of the existing Ishi chatbot. The gateway calls AI Engine's chatbot API, preserving its configured Knowledge, Discussions and tools.</p></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ishi-manychat-key">ManyChat Account Public API key</label></th>
                        <td><input id="ishi-manychat-key" type="password" autocomplete="new-password" class="regular-text" name="<?php echo esc_attr( self::OPTION ); ?>[manychat_api_key]" value="" placeholder="Leave blank to keep the existing key"><p class="description">Legacy ManyChat only. Recommended: define <code>ISHI_SOCIAL_MANYCHAT_API_KEY</code> in wp-config.php instead of storing it in WordPress.</p></td>
                    </tr>
                    <tr>
                        <th scope="row">Per-contact AI requests/minute</th>
                        <td><input type="number" min="1" max="60" name="<?php echo esc_attr( self::OPTION ); ?>[per_contact_limit]" value="<?php echo esc_attr( $settings['per_contact_limit'] ); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row">Global AI requests/minute</th>
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
            <h2>Chatfuel bridge token</h2>
            <p>Use only for the Node bridge → <code>/respond</code> request. It is independent from the Chatfuel API token, OpenAI, Easy MCP, PayMongo, Short.io, and WordPress credentials. Only its SHA-256 hash is stored.</p>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <input type="hidden" name="action" value="ishi_social_ai_rotate_chatfuel_token">
                <?php wp_nonce_field( 'ishi_social_ai_rotate_chatfuel_token' ); ?>
                <?php submit_button( self::chatfuel_token_hash() ? 'Rotate Chatfuel Bridge Token' : 'Generate Chatfuel Bridge Token', 'secondary' ); ?>
            </form>

            <h2>Legacy gateway token</h2>
            <p>Used by the existing ManyChat <code>/message</code>, <code>/state</code>, and <code>/health</code> routes. Only its SHA-256 hash is stored.</p>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <input type="hidden" name="action" value="ishi_social_ai_rotate_token">
                <?php wp_nonce_field( 'ishi_social_ai_rotate_token' ); ?>
                <?php submit_button( self::gateway_token_hash() ? 'Rotate Legacy Gateway Token' : 'Generate Legacy Gateway Token', 'secondary' ); ?>
            </form>
        </div>
        <?php
    }
}

register_activation_hook( __FILE__, [ Gateway::class, 'activate' ] );
Gateway::boot();
