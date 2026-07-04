class CargoScanner < Formula
  desc "Scan inbound artifacts before unpacking them"
  homepage "https://github.com/opencomputinggarage/cargo-scanner"
  license "Apache-2.0"
  head "https://github.com/opencomputinggarage/cargo-scanner.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X main.version=#{version}"
    system "go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin/"cargo-scanner", "./cmd/cargo-scanner"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cargo-scanner version")
  end
end
