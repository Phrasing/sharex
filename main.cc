// clang-format off
#include <mongoose.c>
#include <mongoose.h>
#include <thread>
#include <future>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>
#include <cassert>
#include <unordered_map>
// clang-format on

namespace {
constexpr const char *kHttpsBindAddress = "http://0.0.0.0:443";

constexpr const char *kRootDir = "/home/weed/sharex-server";
constexpr const char *kUploadDir = "/home/weed/sharex-server/i";

constexpr const char *kApiUsername = "bob@example.com";
constexpr const char *kApiPassword = "example123";

constexpr const char *kCertFile = "cert.pem";
constexpr const char *kCertKeyFile = "privkey.pem";

constexpr uint64_t kMaxFileSize = 1024 * 1024 * 1024;

enum http_status {
  HTTP_STATUS_OK = 200,
  HTTP_STATUS_BAD_REQUEST = 400,
  HTTP_STATUS_UNAUTHORIZED = 401,
  HTTP_STATUS_NOT_FOUND = 404,
  HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
};

struct server_context {
  ::mg_http_serve_opts opts{};
  ::mg_tls_opts tls_opts{};
};

struct mg_str_wrapper {
  mg_str_wrapper(const char *ptr, size_t len) : str_{ptr, len} {}
  mg_str_wrapper(::mg_str str) : str_(str) {}
  ~mg_str_wrapper() {
    free((void *)this->str_.ptr);
    this->str_.ptr = nullptr;
  }
  ::mg_str str_{};
};

struct connection_state {
  std::future<http_status> future{};
};

void create_mg_context(server_context *ctx) {
  ctx->opts = ::mg_http_serve_opts{.root_dir = kRootDir};
  ctx->tls_opts = ::mg_tls_opts{
      .cert = kCertFile,
      .certkey = kCertKeyFile,
  };
}

http_status handle_file_upload(std::unique_ptr<::mg_str_wrapper> body) {
  ::mg_http_part part{};
  size_t pos = 0;
  while ((pos = ::mg_http_next_multipart(body->str_, pos, &part)) != 0) {
    char buf[MG_PATH_MAX]{};
    size_t length =
        ::mg_snprintf(buf, sizeof(buf), "%s/%.*s", kUploadDir,
                      static_cast<int>(part.filename.len), part.filename.ptr);
    buf[length] = '\0';

    const auto filtered_path = ::mg_remove_double_dots(buf);
    std::string_view path_view = {filtered_path, ::strlen(filtered_path)};

    if (part.body.len > kMaxFileSize) {
      return http_status::HTTP_STATUS_BAD_REQUEST;
    }

    if (!::mg_file_write(&mg_fs_posix, path_view.data(), part.body.ptr,
                         part.body.len)) {
      return http_status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }
  }
  return http_status::HTTP_STATUS_OK;
}

bool is_authorized_api_request(::mg_http_message *msg,
                               std::string_view username,
                               std::string_view password) {
  char user[64], pw[64]{};
  ::mg_http_creds(msg, user, sizeof(user), pw, sizeof(pw));
  return (username == user && password == pw);
}

void event_handler(::mg_connection *c, int ev, void *ev_data, void *fn_data) {
  auto *ctx = static_cast<server_context *>(fn_data);

  if (ev == ::MG_EV_ACCEPT && ctx != nullptr) {
    ::mg_tls_init(c, &ctx->tls_opts);
  } else if (ev == ::MG_EV_HTTP_MSG) {
    auto *msg = static_cast<::mg_http_message *>(ev_data);

    if (::mg_http_match_uri(msg, "/api/upload") &&
        ::mg_vcasecmp(&msg->method, "POST") == 0) {
      if (is_authorized_api_request(msg, kApiUsername, kApiPassword)) {
        auto *state = reinterpret_cast<connection_state *>(
            calloc(1, sizeof(connection_state)));

        state->future = std::async(std::launch::async, &handle_file_upload,
                                   std::move(std::make_unique<mg_str_wrapper>(
                                       ::mg_strdup(msg->body))));

        *reinterpret_cast<void **>(c->data) = state;
      } else {
        ::mg_http_reply(c, http_status::HTTP_STATUS_UNAUTHORIZED, "", "");
      }
    } else {
      ::mg_http_serve_dir(c, static_cast<::mg_http_message *>(ev_data),
                          &ctx->opts);
    }
  } else if (ev == ::MG_EV_POLL) {
    auto *state = *reinterpret_cast<connection_state **>(c->data);
    if (state != nullptr && state->future.wait_for(std::chrono::seconds(0)) ==
                                std::future_status::ready) {
      auto *state_ptr = *reinterpret_cast<void **>(c->data);
      ::mg_http_reply(c, state->future.get(), "", "");
      free(state_ptr);
      state_ptr = nullptr;
    }
  }
}
}  // namespace

int32_t main(void) {
  mg_mgr mgr{};
  ::mg_log_set(MG_LL_INFO);
  ::mg_mgr_init(&mgr);

  server_context ctx{};
  create_mg_context(&ctx);
  ::mg_http_listen(&mgr, kHttpsBindAddress, event_handler, &ctx);

  for (;;) ::mg_mgr_poll(&mgr, 10);
  ::mg_mgr_free(&mgr);
  return 0;
}
