#pragma once
#include <armflow/binary_image.hpp>
#include <functional>
#include <map>
#include <memory>
namespace armflow {
class ShimContext {
public:
  virtual ~ShimContext() = default;
  virtual std::uint64_t argument(unsigned index) const = 0;
  virtual ByteBuffer read(Address pointer, std::size_t length) const = 0;
  virtual void write(Address pointer, std::span<const std::uint8_t> bytes) = 0;
  virtual Address allocate(std::size_t length) = 0;
  virtual std::size_t allocation_size(Address pointer) const = 0;
  virtual void release(Address pointer) = 0;
  virtual void return_value(std::uint64_t value) = 0;
};
using ShimHandler = std::function<void(ShimContext &)>;
class ShimRegistry {
public:
  void define(std::string name, ShimHandler model);
  const ShimHandler &lookup(const std::string &name) const;
  static std::shared_ptr<const ShimRegistry> standard();

private:
  std::map<std::string, ShimHandler> models_;
};
} // namespace armflow
