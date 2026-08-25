# frozen_string_literal: true

require "endpoint_security"

def rss_bytes
  Integer(IO.popen(["/bin/ps", "-o", "rss=", "-p", Process.pid.to_s], &:read).strip) * 1024
end

deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + (Integer(ENV.fetch("HOURS", "24")) * 3600)
ES::Client.open do |client|
  client.subscribe(ES::EventType.all_notify)
  ES::EventType.all_notify.each { |event| client.on(event) { |_message| nil } }
  client.start
  sleep(Integer(ENV.fetch("WARMUP_SECONDS", "60")))
  baseline = rss_bytes
  sleep(60) while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
  stats = client.stats
  growth = (rss_bytes - baseline).fdiv(baseline)
  warn stats.merge(rss_growth: growth).inspect
  abort "watchdog timeouts occurred" unless stats[:timeouts].zero?
  abort "RSS grew by more than 5%" if growth > 0.05
end
