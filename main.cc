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
// clang-format on

namespace {
constexpr const char *kHttpBindAddress = "http://0.0.0.0:80";
constexpr const char *kHttpsBindAddress = "http://0.0.0.0:443";

constexpr const char *kRootDir = "/home/weed/sharex-server";
constexpr const char *kUploadDir = "/home/weed/sharex-server/i";

constexpr const char *kApiUsername = "bob@example.com";
constexpr const char *kApiPassword = "example123";

constexpr uint64_t kMaxFileSize = 1024 * 1024 * 1024;

enum http_status {
  HTTP_STATUS_OK = 200,
  HTTP_STATUS_BAD_REQUEST = 400,
  HTTP_STATUS_UNAUTHORIZED = 401,
  HTTP_STATUS_NOT_FOUND = 404,
  HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
};

struct server_context {
  bool use_tls = false;
  ::mg_http_serve_opts opts{};
  std::vector<std::future<int>> io_futures_{};
};

void create_mg_context(server_context *ctx, bool use_tls = false) {
  ctx->use_tls = use_tls;
  ctx->opts = ::mg_http_serve_opts{.root_dir = kRootDir};
}

int handle_file_upload(::mg_str body) {
  ::mg_http_part part{};
  size_t pos = 0;
  while ((pos = ::mg_http_next_multipart(body, pos, &part)) != 0) {
    char buf[MG_PATH_MAX]{};
    size_t length =
        ::mg_snprintf(buf, sizeof(buf), "%s/%.*s", kUploadDir,
                      static_cast<int>(part.filename.len), part.filename.ptr);
    buf[length] = '\0';

    std::string_view path_view = {buf, length};

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

  if (ev == ::MG_EV_ACCEPT && ctx->use_tls) {
    ::mg_tls_opts opts = {
        .cert = "cert.pem",
        .certkey = "privkey.pem",
    };
    ::mg_tls_init(c, &opts);
  } else if (ev == ::MG_EV_HTTP_MSG) {
    auto *msg = static_cast<::mg_http_message *>(ev_data);

    if (::mg_http_match_uri(msg, "/api/upload") &&
        ::mg_vcasecmp(&msg->method, "POST") == 0) {
      if (!is_authorized_api_request(msg, kApiUsername, kApiPassword)) {
        ::mg_http_reply(c, http_status::HTTP_STATUS_UNAUTHORIZED, "",
                        "Unauthorized");
        return;
      }

      const ::mg_str body = ::mg_strdup(msg->body);
      ctx->io_futures_.push_back(
          std::async(std::launch::async, &handle_file_upload, body));

    } else {
      ::mg_http_serve_dir(c, static_cast<::mg_http_message *>(ev_data),
                          &ctx->opts);
    }
  } else if (ev == ::MG_EV_POLL) {
    for (auto it = ctx->io_futures_.begin(); it != ctx->io_futures_.end();) {
      if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        ::mg_http_reply(c, it->get(), "", "");
        it = ctx->io_futures_.erase(it);
      } else {
        ++it;
      }
    }
  }
}
}  // namespace

int main(void) {
  mg_mgr mgr{};
  ::mg_log_set(MG_LL_INFO);
  ::mg_mgr_init(&mgr);

  server_context http_context{};
  server_context https_context{};

  create_mg_context(&http_context);
  create_mg_context(&https_context, true);

  ::mg_http_listen(&mgr, kHttpBindAddress, event_handler, &http_context);
  ::mg_http_listen(&mgr, kHttpsBindAddress, event_handler, &https_context);

  for (;;) ::mg_mgr_poll(&mgr, 10);
  ::mg_mgr_free(&mgr);
  return 0;
}
