# frozen_string_literal: true

require 'digest'
require 'json'
require 'optparse'

module Paint
  R = "\e[0m"
  def self.red(s)    = "\e[31m#{s}#{R}"
  def self.green(s)  = "\e[32m#{s}#{R}"
  def self.yellow(s) = "\e[33m#{s}#{R}"
  def self.cyan(s)   = "\e[36m#{s}#{R}"
  def self.bold(s)   = "\e[1m#{s}#{R}"
  def self.dim(s)    = "\e[90m#{s}#{R}"
end

module Hashing
  ALGOS = %w[md5 sha1 sha256 sha512].freeze

  def self.digest(algo, input)
    case algo
    when 'md5'    then Digest::MD5.hexdigest(input)
    when 'sha1'   then Digest::SHA1.hexdigest(input)
    when 'sha256' then Digest::SHA256.hexdigest(input)
    when 'sha512' then Digest::SHA512.hexdigest(input)
    else raise ArgumentError, "unknown algo: #{algo}"
    end
  end

  def self.sniff(hash)
    { 32 => 'md5', 40 => 'sha1', 64 => 'sha256', 128 => 'sha512' }[hash.length]
  end

  def self.hex?(hash)
    hash.match?(/\A[0-9a-fA-F]+\z/)
  end
end

class Table
  FILE = 'table.json'

  def initialize(path = FILE)
    @path = path
    @data = {}
    slurp
  end

  def hit(algo, hash)
    @data.dig(algo, hash.downcase)
  end

  def put(algo, hash, plain)
    @data[algo] ||= {}
    @data[algo][hash.downcase] = plain
  end

  def ingest(words, algos = Hashing::ALGOS)
    n = 0
    words.each do |w|
      algos.each do |a|
        h = Hashing.digest(a, w)
        next if @data.dig(a, h)
        put(a, h, w)
        n += 1
      end
    end
    n
  end

  def flush
    File.write(@path, JSON.pretty_generate(@data))
  end

  def counts
    @data.transform_values(&:size)
  end

  def total
    @data.values.sum(&:size)
  end

  private

  def slurp
    return unless File.exist?(@path)
    raw = JSON.parse(File.read(@path))
    raw.each { |a, pairs| @data[a] = pairs.transform_keys(&:downcase) }
  rescue JSON::ParserError => e
    warn Paint.yellow("bad table file: #{e.message}")
  end
end

class Bruteforce
  SETS = {
    'digits'    => ('0'..'9').to_a,
    'lower'     => ('a'..'z').to_a,
    'upper'     => ('A'..'Z').to_a,
    'alpha'     => ('a'..'z').to_a + ('A'..'Z').to_a,
    'alnum'     => ('0'..'9').to_a + ('a'..'z').to_a + ('A'..'Z').to_a,
    'printable' => (33..126).map(&:chr),
  }.freeze

  attr_reader :tried

  def initialize(set: 'alnum', min: 1, max: 4)
    @chars = SETS.fetch(set) { raise ArgumentError, "unknown charset: #{set}" }
    @min   = min
    @max   = max
    @tried = 0
  end

  def each
    (@min..@max).each { |len| emit(len) { |c| yield c } }
  end

  def estimate
    (@min..@max).sum { |l| @chars.size**l }
  end

  private

  def emit(len)
    base = @chars.size
    (base**len).times do |i|
      word = Array.new(len) do |pos|
        @chars[(i / base**(len - 1 - pos)) % base]
      end.join
      @tried += 1
      yield word
    end
  end
end

class Cracker
  SPIN = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏].freeze

  def initialize(hash:, algo: nil, table: nil)
    @hash  = hash.downcase.strip
    @algo  = algo || Hashing.sniff(@hash)
    @table = table || Table.new
    @si    = 0

    raise ArgumentError, "can't detect algo for length #{@hash.length}" unless @algo
    raise ArgumentError, 'not a valid hex string'                        unless Hashing.hex?(@hash)
  end

  def try_table
    puts "\n#{Paint.bold('[ table ]')}"
    found = @table.hit(@algo, @hash)
    if found
      win(found, 'table')
      return found
    end
    puts Paint.dim("  miss (#{@table.counts[@algo] || 0} #{@algo.upcase} entries)")
    nil
  end

  def try_wordlist(path)
    puts "\n#{Paint.bold('[ wordlist ]')} #{Paint.dim(path)}"
    unless File.exist?(path)
      puts Paint.red("  not found: #{path}")
      return nil
    end

    n  = 0
    t0 = Time.now

    File.foreach(path) do |line|
      word = line.chomp
      next if word.empty?
      n += 1
      tick(n, word) if (n % 5_000).zero?

      if Hashing.digest(@algo, word) == @hash
        wipe
        win(word, "wordlist after #{n} words, #{age(t0)}")
        @table.put(@algo, @hash, word)
        return word
      end
    end

    wipe
    puts Paint.dim("  #{n} words, no match (#{age(t0)})")
    nil
  end

  def try_brute(set: 'alnum', min: 1, max: 4)
    bf  = Bruteforce.new(set: set, min: min, max: max)
    est = commas(bf.estimate)
    puts "\n#{Paint.bold('[ brute ]')} #{Paint.dim("#{set} #{min}..#{max} ~#{est}")}"

    t0  = Time.now
    out = nil

    bf.each do |w|
      tick(bf.tried, w) if (bf.tried % 20_000).zero?

      if Hashing.digest(@algo, w) == @hash
        wipe
        win(w, "brute after #{commas(bf.tried)}, #{age(t0)}")
        @table.put(@algo, @hash, w)
        out = w
        break
      end
    end

    unless out
      wipe
      puts Paint.dim("  #{commas(bf.tried)} tried, no match (#{age(t0)})")
    end

    out
  end

  private

  def win(plain, via)
    puts "\n  #{Paint.green('✔ cracked')}  #{Paint.bold(plain)}  #{Paint.dim("(#{via})")}"
    puts "  #{Paint.dim("algo: #{@algo.upcase}  hash: #{@hash}")}"
  end

  def tick(n, cur)
    @si = (@si + 1) % SPIN.size
    preview = cur.length > 12 ? "#{cur[0..11]}…" : cur.ljust(13)
    print "\r  #{Paint.cyan(SPIN[@si])} #{commas(n).rjust(12)}  #{Paint.dim(preview)}  "
  end

  def wipe      = print("\r\e[2K")
  def age(t)    = "#{(Time.now - t).round(2)}s"
  def commas(n) = n.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\1,').reverse
end

# ── cli ──────────────────────────────────────

WLIST = File.join(__dir__, 'wordlist.txt')

opts = {
  algo: nil, wordlist: WLIST, set: 'alnum',
  min: 1, max: 4, build: false,
  tpath: Table::FILE,
  skip_table: false, skip_words: false, skip_brute: false,
}

op = OptionParser.new do |o|
  o.banner = "#{Paint.bold(Paint.cyan('cracker'))} — md5/sha1/sha256/sha512\nusage: ruby cracker.rb [opts] <hash>\n"
  o.on('-a', '--algo A',      'force algo')          { |v| opts[:algo]       = v.downcase }
  o.on('-w', '--wordlist F',  'wordlist path')       { |v| opts[:wordlist]   = v }
  o.on('-c', '--charset N',   'brute charset')       { |v| opts[:set]        = v }
  o.on(      '--min N', Integer)                     { |v| opts[:min]        = v }
  o.on(      '--max N', Integer)                     { |v| opts[:max]        = v }
  o.on(      '--table F',     'table path')          { |v| opts[:tpath]      = v }
  o.on(      '--build',       'build table + exit')  { opts[:build]          = true }
  o.on(      '--no-table')                           { opts[:skip_table]     = true }
  o.on(      '--no-words')                           { opts[:skip_words]     = true }
  o.on(      '--no-brute')                           { opts[:skip_brute]     = true }
  o.on('-h', '--help')                               { puts o; exit }
end
op.parse!

if opts[:build]
  t   = Table.new(opts[:tpath])
  wl  = File.readlines(opts[:wordlist], chomp: true).reject(&:empty?)
  n   = t.ingest(wl)
  t.flush
  puts Paint.green("built — #{n} new entries, #{t.total} total → #{opts[:tpath]}")
  t.counts.each { |a, c| puts "  #{a.upcase.ljust(8)} #{c}" }
  exit
end

target = ARGV.shift
if target.nil? || target.empty?
  puts op
  exit 1
end

puts "#{Paint.bold('target')} #{Paint.yellow(target)}"
puts "#{Paint.bold('algo')}   #{(opts[:algo] || Hashing.sniff(target) || '?').upcase}\n"

tbl = Table.new(opts[:tpath])
c   = Cracker.new(hash: target, algo: opts[:algo], table: tbl)

result = nil
result ||= c.try_table                                                        unless opts[:skip_table]
result ||= c.try_wordlist(opts[:wordlist])                                    unless opts[:skip_words] || result
result ||= c.try_brute(set: opts[:set], min: opts[:min], max: opts[:max])    unless opts[:skip_brute] || result

if result
  tbl.flush
  puts Paint.dim("\n  table saved → #{opts[:tpath]}")
else
  puts "\n#{Paint.red('  ✘ not cracked')}"
  puts Paint.dim('  try: bigger wordlist, --max 5, --charset printable')
end

puts
