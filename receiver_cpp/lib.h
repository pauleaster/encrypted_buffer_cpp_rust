#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>


struct Receiver {
  const char *certificate_data;
  const char *private_key_data;
  const char *receiver_ip;
};

extern "C" {

Receiver *receiver_new(const char *certificate_env_var,
                       const char *private_key_env_var,
                       const char *receiver_ip,
                       uint16_t port);

char *run(Receiver *self);

void receiver_free(Receiver *receiver);

} // extern "C"
