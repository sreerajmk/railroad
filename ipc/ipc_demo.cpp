#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
constexpr const char* kSharedMemoryName = "/railroad_ipc_shared";
constexpr const char* kMessageQueueName = "/railroad_ipc_queue";
constexpr std::size_t kSharedMemorySize = 4096;

struct SharedState {
    std::uint64_t sequence = 0;
    char message[128] = "idle";
};

struct QueueMessage {
    std::uint64_t sequence = 0;
    char text[128] = "";
};

class SharedMemory {
public:
    SharedMemory(const std::string& name, std::size_t size, bool create)
        : name_(name), size_(size), fd_(-1), data_(nullptr) {
        int flags = O_RDWR;
        if (create) {
            flags |= O_CREAT;
            shm_unlink(name_.c_str());
        }

        fd_ = shm_open(name_.c_str(), flags, 0666);
        if (fd_ == -1) {
            throw std::runtime_error("shm_open failed: " + std::string(strerror(errno)));
        }

        if (create) {
            if (ftruncate(fd_, static_cast<off_t>(size_)) == -1) {
                throw std::runtime_error("ftruncate failed: " + std::string(strerror(errno)));
            }
        }

        data_ = mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
        if (data_ == MAP_FAILED) {
            throw std::runtime_error("mmap failed: " + std::string(strerror(errno)));
        }
    }

    ~SharedMemory() {
        if (data_ != nullptr && data_ != MAP_FAILED) {
            munmap(data_, size_);
        }
        if (fd_ != -1) {
            close(fd_);
        }
    }

    void* data() const { return data_; }

    template <typename T>
    T* typed_data() const {
        return static_cast<T*>(data_);
    }

private:
    std::string name_;
    std::size_t size_;
    int fd_;
    void* data_;
};

class MessageQueue {
public:
    MessageQueue(const std::string& name, bool create)
        : name_(name), queue_(reinterpret_cast<mqd_t>(-1)) {
        mq_attr attr{};
        attr.mq_flags = 0;
        attr.mq_maxmsg = 10;
        attr.mq_msgsize = sizeof(QueueMessage);
        attr.mq_curmsgs = 0;

        if (create) {
            mq_unlink(name_.c_str());
            queue_ = mq_open(name_.c_str(), O_CREAT | O_RDWR, 0666, &attr);
        } else {
            queue_ = mq_open(name_.c_str(), O_RDWR);
        }

        if (queue_ == reinterpret_cast<mqd_t>(-1)) {
            throw std::runtime_error("mq_open failed: " + std::string(strerror(errno)));
        }
    }

    ~MessageQueue() {
        if (queue_ != reinterpret_cast<mqd_t>(-1)) {
            mq_close(queue_);
        }
    }

    void send(const QueueMessage& message) {
        const auto* bytes = reinterpret_cast<const char*>(&message);
        if (mq_send(queue_, bytes, sizeof(message), 1) == -1) {
            throw std::runtime_error("mq_send failed: " + std::string(strerror(errno)));
        }
    }

    QueueMessage receive() {
        char buffer[sizeof(QueueMessage)] = {};
        unsigned int priority = 0;
        const auto bytes = mq_receive(queue_, buffer, sizeof(buffer), &priority);
        if (bytes == -1) {
            throw std::runtime_error("mq_receive failed: " + std::string(strerror(errno)));
        }

        QueueMessage result{};
        const auto length = static_cast<std::size_t>(bytes);
        if (length > sizeof(result)) {
            throw std::runtime_error("Received message larger than expected");
        }

        std::memcpy(&result, buffer, length);
        return result;
    }

private:
    std::string name_;
    mqd_t queue_;
};

void run_producer() {
    std::cout << "[producer] creating shared memory and queue\n";
    SharedMemory shared(kSharedMemoryName, kSharedMemorySize, true);
    MessageQueue queue(kMessageQueueName, true);

    auto* state = shared.typed_data<SharedState>();
    state->sequence = 1;
    std::snprintf(state->message, sizeof(state->message), "producer ready");

    QueueMessage payload{};
    payload.sequence = state->sequence;
    std::snprintf(payload.text, sizeof(payload.text), "hello from producer");

    queue.send(payload);

    std::cout << "[producer] shared memory: seq=" << state->sequence
              << ", message='" << state->message << "'\n";
    std::cout << "[producer] queued message: seq=" << payload.sequence
              << ", text='" << payload.text << "'\n";

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "[producer] leaving shared memory and queue available for consumer\n";
}

void run_consumer() {
    std::cout << "[consumer] opening shared memory and queue\n";
    SharedMemory shared(kSharedMemoryName, kSharedMemorySize, false);
    MessageQueue queue(kMessageQueueName, false);

    const auto message = queue.receive();
    auto* state = shared.typed_data<SharedState>();

    state->sequence = message.sequence + 1;
    std::snprintf(state->message, sizeof(state->message), "processed by consumer");

    std::cout << "[consumer] received message: seq=" << message.sequence
              << ", text='" << message.text << "'\n";
    std::cout << "[consumer] updated shared memory: seq=" << state->sequence
              << ", message='" << state->message << "'\n";

    std::cout << "[consumer] cleanup complete; queue and shared memory remain available for follow-up demos\n";
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: railroad_ipc <producer|consumer>\n";
        return 1;
    }

    const std::string mode = argv[1];
    try {
        if (mode == "producer") {
            run_producer();
            return 0;
        }

        if (mode == "consumer") {
            run_consumer();
            return 0;
        }

        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "IPC error: " << ex.what() << "\n";
        return 2;
    }
}
