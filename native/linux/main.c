/* Trusted local UI only. Service content is opened by the user's own clients. */
#include <gtk/gtk.h>
#include <webkit/webkit.h>
#include <libsoup/soup.h>
#include <gio/gunixsocketaddress.h>
#include <sys/stat.h>
#include <unistd.h>

static SoupSession *backend;
static WebKitWebView *view;
static GtkWindow *window;
static const char *socket_path;
static GCancellable *camera_prompt;
static gboolean closing;
static const char *csp = "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-src 'none'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

typedef struct { WebKitURISchemeRequest *request; SoupMessage *message; } Call;

static gboolean local_uri(const char *uri) {
    if (!uri) return FALSE;
    GUri *u = g_uri_parse(uri, G_URI_FLAGS_ENCODED, NULL);
    gboolean ok = u && g_strcmp0(g_uri_get_scheme(u), "torkitten") == 0 &&
        g_strcmp0(g_uri_get_host(u), "app") == 0 &&
        !g_uri_get_userinfo(u) && g_uri_get_port(u) == -1;
    if (u) g_uri_unref(u);
    return ok;
}

static void fail_request(WebKitURISchemeRequest *request, const char *message) {
    GError *error = g_error_new_literal(G_IO_ERROR, G_IO_ERROR_FAILED, message);
    webkit_uri_scheme_request_finish_error(request, error);
    g_error_free(error);
}

static void answered(GObject *source, GAsyncResult *result, gpointer data) {
    Call *call = data;
    GError *error = NULL;
    GBytes *bytes = soup_session_send_and_read_finish(SOUP_SESSION(source), result, &error);
    if (!bytes || g_bytes_get_size(bytes) > 2 * 1024 * 1024) {
        fail_request(call->request, "Private app API request failed");
    } else {
        GInputStream *stream = g_memory_input_stream_new_from_bytes(bytes);
        WebKitURISchemeResponse *response = webkit_uri_scheme_response_new(stream, g_bytes_get_size(bytes));
        SoupMessageHeaders *headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_RESPONSE);
        SoupMessageHeaders *upstream = soup_message_get_response_headers(call->message);
        const char *type = soup_message_headers_get_one(upstream, "Content-Type");
        const char *disposition = soup_message_headers_get_one(upstream, "Content-Disposition");
        soup_message_headers_replace(headers, "Content-Type", type ? type : "application/octet-stream");
        soup_message_headers_replace(headers, "Content-Security-Policy", csp);
        soup_message_headers_replace(headers, "Cache-Control", "no-store");
        soup_message_headers_replace(headers, "X-Content-Type-Options", "nosniff");
        soup_message_headers_replace(headers, "Referrer-Policy", "no-referrer");
        if (disposition) soup_message_headers_replace(headers, "Content-Disposition", disposition);
        webkit_uri_scheme_response_set_status(response, soup_message_get_status(call->message), NULL);
        webkit_uri_scheme_response_set_content_type(response, type ? type : "application/octet-stream");
        webkit_uri_scheme_response_set_http_headers(response, headers);
        webkit_uri_scheme_request_finish_with_response(call->request, response);
        g_object_unref(response);
        g_object_unref(stream);
    }
    g_clear_error(&error);
    if (bytes) g_bytes_unref(bytes);
    g_object_unref(call->message);
    g_object_unref(call->request);
    g_free(call);
}

static void request(WebKitURISchemeRequest *request, gpointer unused) {
    (void)unused;
    const char *uri = webkit_uri_scheme_request_get_uri(request);
    if (webkit_uri_scheme_request_get_web_view(request) != view || !local_uri(uri)) {
        fail_request(request, "Untrusted UI origin");
        return;
    }
    GUri *u = g_uri_parse(uri, G_URI_FLAGS_ENCODED, NULL);
    const char *query = g_uri_get_query(u);
    char *url = g_strdup_printf("http://app%s%s%s", g_uri_get_path(u), query ? "?" : "", query ? query : "");
    SoupMessage *message = soup_message_new(webkit_uri_scheme_request_get_http_method(request), url);
    g_free(url);
    g_uri_unref(u);
    if (!message) { fail_request(request, "Invalid local request"); return; }
    soup_message_set_flags(message, SOUP_MESSAGE_NO_REDIRECT);
    SoupMessageHeaders *headers = soup_message_get_request_headers(message);
    soup_message_headers_replace(headers, "Origin", "torkitten://app");
    GInputStream *body = webkit_uri_scheme_request_get_http_body(request);
    if (body) {
        gsize count = 0;
        char *buffer = g_malloc(2 * 1024 * 1024 + 1);
        GError *error = NULL;
        if (!g_input_stream_read_all(body, buffer, 2 * 1024 * 1024 + 1, &count, NULL, &error) || count > 2 * 1024 * 1024) {
            g_free(buffer); g_clear_error(&error); g_object_unref(message); g_object_unref(body);
            fail_request(request, "Request body exceeds limit or could not be read"); return;
        }
        GBytes *bytes = g_bytes_new_take(buffer, count);
        g_object_unref(body);
        const char *type = soup_message_headers_get_one(webkit_uri_scheme_request_get_http_headers(request), "Content-Type");
        soup_message_set_request_body_from_bytes(message, type ? type : "application/octet-stream", bytes);
        g_bytes_unref(bytes);
    }
    Call *call = g_new0(Call, 1);
    call->request = g_object_ref(request); call->message = message;
    soup_session_send_and_read_async(backend, message, G_PRIORITY_DEFAULT, NULL, answered, call);
}

static gboolean policy(WebKitWebView *v, WebKitPolicyDecision *decision, WebKitPolicyDecisionType type, gpointer unused) {
    (void)v; (void)unused;
    if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {
        webkit_policy_decision_ignore(decision); return TRUE;
    }
    if (type == WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION) {
        WebKitNavigationAction *action = webkit_navigation_policy_decision_get_navigation_action(WEBKIT_NAVIGATION_POLICY_DECISION(decision));
        const char *uri = webkit_uri_request_get_uri(webkit_navigation_action_get_request(action));
        if (g_str_has_prefix(uri, "blob:torkitten://app/")) {
            webkit_policy_decision_download(decision); return TRUE;
        }
        if (!local_uri(uri)) { webkit_policy_decision_ignore(decision); return TRUE; }
    }
    return FALSE;
}

static void camera_answered(GObject *dialog, GAsyncResult *result, gpointer data) {
    WebKitPermissionRequest *request = data; GError *error = NULL;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(dialog), result, &error);
    if (choice == 1 && !error && !closing && local_uri(webkit_web_view_get_uri(view)))
        webkit_permission_request_allow(request);
    else webkit_permission_request_deny(request);
    g_clear_error(&error); g_clear_object(&camera_prompt); g_object_unref(request);
}

static gboolean permission(WebKitWebView *v, WebKitPermissionRequest *request, gpointer unused) {
    (void)unused;
    gboolean allowed = !closing && !camera_prompt && v == view && local_uri(webkit_web_view_get_uri(v)) &&
        WEBKIT_IS_USER_MEDIA_PERMISSION_REQUEST(request);
    if (allowed) {
        WebKitUserMediaPermissionRequest *media = WEBKIT_USER_MEDIA_PERMISSION_REQUEST(request);
        allowed = webkit_user_media_permission_is_for_video_device(media) &&
            !webkit_user_media_permission_is_for_audio_device(media) && !webkit_user_media_permission_is_for_display_device(media);
    }
    if (!allowed) { webkit_permission_request_deny(request); return TRUE; }
    GtkAlertDialog *dialog = gtk_alert_dialog_new("Allow the camera to scan a connection QR code?");
    const char *buttons[] = {"Deny", "Allow camera", NULL};
    gtk_alert_dialog_set_detail(dialog, "Frames are decoded locally in TorKitten. Microphone access is not allowed.");
    gtk_alert_dialog_set_buttons(dialog, buttons); gtk_alert_dialog_set_cancel_button(dialog, 0); gtk_alert_dialog_set_default_button(dialog, 0);
    camera_prompt = g_cancellable_new();
    gtk_alert_dialog_choose(dialog, window, camera_prompt, camera_answered, g_object_ref(request));
    g_object_unref(dialog); return TRUE;
}

static gboolean close_camera(GtkWindow *w, gpointer unused) {
    (void)w; (void)unused; closing = TRUE;
    if (camera_prompt) g_cancellable_cancel(camera_prompt);
    webkit_web_view_set_camera_capture_state(view, WEBKIT_MEDIA_CAPTURE_STATE_NONE);
    return FALSE;
}

static void saved(GObject *dialog, GAsyncResult *result, gpointer data) {
    WebKitDownload *download = data;
    GError *error = NULL;
    GFile *file = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(dialog), result, &error);
    char *path = file ? g_file_get_path(file) : NULL;
    if (path) webkit_download_set_destination(download, path);
    else webkit_download_cancel(download);
    g_free(path); g_clear_object(&file); g_clear_error(&error); g_object_unref(download);
}

static gboolean destination(WebKitDownload *download, const char *suggested, gpointer unused) {
    (void)unused;
    if (!g_str_has_suffix(suggested, ".age")) { webkit_download_cancel(download); return TRUE; }
    GtkFileDialog *dialog = gtk_file_dialog_new();
    char *name = g_path_get_basename(suggested);
    gtk_file_dialog_set_initial_name(dialog, name);
    gtk_file_dialog_save(dialog, window, NULL, saved, g_object_ref(download));
    g_free(name); g_object_unref(dialog); return TRUE;
}

static void download_started(WebKitNetworkSession *session, WebKitDownload *download, gpointer unused) {
    (void)session; (void)unused;
    const char *uri = webkit_uri_request_get_uri(webkit_download_get_request(download));
    if (webkit_download_get_web_view(download) != view || !g_str_has_prefix(uri, "blob:torkitten://app/")) { webkit_download_cancel(download); return; }
    g_signal_connect(download, "decide-destination", G_CALLBACK(destination), NULL);
}

static void activate(GtkApplication *app, gpointer unused) {
    (void)unused;
    GSocketConnectable *address = G_SOCKET_CONNECTABLE(g_unix_socket_address_new(socket_path));
    GProxyResolver *direct = g_simple_proxy_resolver_new("direct://", NULL);
    backend = soup_session_new_with_options("remote-connectable", address, "proxy-resolver", direct, "timeout", 180, NULL);
    g_object_unref(address); g_object_unref(direct);
    WebKitWebContext *context = webkit_web_context_new();
    WebKitNetworkSession *network = webkit_network_session_new_ephemeral();
    WebKitNetworkProxySettings *proxy = webkit_network_proxy_settings_new("socks5://127.0.0.1:0", NULL);
    webkit_network_session_set_proxy_settings(network, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, proxy);
    webkit_network_proxy_settings_free(proxy);
    WebKitSecurityManager *security = webkit_web_context_get_security_manager(context);
    webkit_security_manager_register_uri_scheme_as_secure(security, "torkitten");
    webkit_security_manager_register_uri_scheme_as_cors_enabled(security, "torkitten");
    webkit_security_manager_register_uri_scheme_as_display_isolated(security, "torkitten");
    webkit_web_context_register_uri_scheme(context, "torkitten", request, NULL, NULL);
    view = WEBKIT_WEB_VIEW(g_object_new(WEBKIT_TYPE_WEB_VIEW, "web-context", context, "network-session", network, NULL));
    WebKitSettings *settings = webkit_web_view_get_settings(view);
    webkit_settings_set_enable_developer_extras(settings, FALSE);
    webkit_settings_set_enable_media_stream(settings, TRUE);
    webkit_settings_set_enable_html5_database(settings, FALSE);
    webkit_settings_set_enable_html5_local_storage(settings, FALSE);
    webkit_settings_set_allow_file_access_from_file_urls(settings, FALSE);
    webkit_settings_set_allow_universal_access_from_file_urls(settings, FALSE);
    g_signal_connect(view, "decide-policy", G_CALLBACK(policy), NULL);
    g_signal_connect(view, "permission-request", G_CALLBACK(permission), NULL);
    g_signal_connect(network, "download-started", G_CALLBACK(download_started), NULL);
    window = GTK_WINDOW(gtk_application_window_new(app));
    g_signal_connect(window, "close-request", G_CALLBACK(close_camera), NULL);
    gtk_window_set_title(window, "TorKitten"); gtk_window_set_default_size(window, 1000, 720);
    gtk_window_set_child(window, GTK_WIDGET(view));
    webkit_web_view_load_uri(view, "torkitten://app/"); gtk_window_present(window);
    g_object_unref(context); g_object_unref(network);
}

int main(int argc, char **argv) {
    struct stat st;
    if (argc != 2 || argv[1][0] != '/' || lstat(argv[1], &st) || !S_ISSOCK(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077)) {
        g_printerr("usage: torkitten-native /absolute/private/admin.sock (owned Unix socket, mode0600)\n"); return 1;
    }
    socket_path = argv[1]; umask(0077);
    GtkApplication *app = gtk_application_new("org.openresearchtools.TorKitten", G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(app), 1, argv);
    g_object_unref(app); g_clear_object(&backend); return status;
}
