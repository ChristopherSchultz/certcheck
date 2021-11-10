package net.christopherschultz.certcheck;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;
import java.util.TreeSet;

/**
 * Checks X509 certificates to see if they are valid.
 *
 * @author Christopher Schultz
 */
public class CertificateExpirationChecker {
    static void usage(PrintStream out) {
        // Are we running from a JAR file? What's it's name?
        URL url = CertificateExpirationChecker.class.getClassLoader().getResource("META-INF/maven/net.christopherschultz.certcheck/certcheck/pom.xml");
        if(null != url && "jar".equals(url.getProtocol())) {
            // Loaded from a JAR file; probably executable
            // jar file name is between first ! and previous / or : of the URL's path
            String source = url.getPath();
            source = source.substring(0, source.indexOf('!'));
            int pos = source.lastIndexOf('/');
            if(pos < 0) {
                pos = source.lastIndexOf(":");
            }
            if(pos < -1) {
                pos = -1;
            }
            source = source.substring(pos + 1);

            out.println("Usage: java -jar " + source + " [options] file [options...] [file...]");
        } else {
            out.println("Usage: java " + CertificateExpirationChecker.class.getName() + " [options] file [options...] [file...]");
        }

        out.println();
        out.println("Options take effect for all files specified on the command-line after the option has been set.");
        out.println();
        out.println("Options:");
        out.println(" -a, --alias <alias>   Specify the alias of the certificate to test within a keystore.");
        out.println(" -c, --critical <days> Specify the number of days before expiration that will be considered 'critical'.");
        out.println(" -d, --debug           Print additional debug output.");
        out.println("     --dn <dn>         Specify the subject name of the certificate to test within a keystore.");
        out.println(" -E, --error-stdout    Print errors to stdout instead of stderr.");
        out.println(" -f, --file <file>     Explicitly state that the next argument will be a file (useful for odd filenames).");
        out.println(" -h, --help            Print this help message and exit.");
        out.println(" -m, --max      <days> Specify the maximum number of days a certificate may be valid from today.");
        out.println(" -o, --options <file>  Specify an options-file where sensitive things like passwords can be specified safely.");
        out.println(" -P, --provider <name> Specifies a security provider to be used (default=any supporting provider).");
        out.println(" -p, --password        Specify the password to be used for all keystores and files (DANGEROUS! Consider using -o).");
        out.println(" -q, --quiet           Do not print anything if all there are no errors or warnings.");
        out.println(" -r, --report          Report the types of keystores supported and exit.");
        out.println(" -s, --silent          Do out print any output; only return exit code.");
        out.println(" -v, --verbose         Print information about all certificates processed.");
        out.println(" -S, --special <name>  Check a special keystore with the specified name (e.g. Windows-MY, KeychainStore, etc.).");
        out.println(" -w, --warning <days>  Specify the number of days before expiration that will be considered 'warning'.");
        out.println(" --                    Indicate that this is the last option and the remainder of arguments are filenames.");
    }

    public static void main(String[] args) throws Exception
    {
        CertificateExpirationChecker cec = new CertificateExpirationChecker();

        int argindex = 0;
        boolean processedFile = false;

        Status status = Status.UNKNOWN;

        for(argindex = 0; argindex < args.length; ++argindex) {
            String arg = args[argindex];

            if("--critical".equals(arg) || "-c".equals(arg)) {
                cec.critDays = Integer.parseInt(args[++argindex]);
            } else if("--warn".equals(arg) || "-w".equals(arg)) {
                cec.warnDays = Integer.parseInt(args[++argindex]);
            } else if("-debug".equals(arg) || "-d".equals(arg)) {
                cec.debug = true;
            } else if("--verbose".equals(arg) || "-v".equals(arg)) {
                cec.verbose = true;
                cec.quiet = false; // Implied
                cec.out = System.out; // Implied, along with 'err' below
                if(!cec.err.equals(System.err) && !cec.err.equals(System.out)) {
                    cec.err = System.err;
                }
            } else if("--password".equals(arg) || "-p".equals(arg)) {
                cec.setKeystorePassword(args[++argindex]);
            } else if("-S".equals(arg) || "--special".equals(arg) ) {
                status = status.max(cec.checkSpecial(args[++argindex]));

                processedFile = true;
            } else if("-P".equals(arg) || "--provider".equals(arg)) {
                cec.provider = Security.getProvider(args[++argindex]);

                if(cec.debug) {
                    cec.out.println("DEBUG: Using provider " + cec.provider.getName());
                }
            } else if("--error-stdout".equals(arg) || "-E".equals(arg)) {
                cec.err = System.out;
            } else if ("--max".equals(arg) || "-m".equals(arg)) {
                cec.maxDays = Integer.parseInt(args[++argindex]);
            } else if("--file".equals(arg) || "-f".equals(arg)) {
                status = status.max(cec.processFilename(args[++argindex]));

                processedFile = true;
            } else if("--alias".equals(arg) || "-a".equals(arg)) {
                cec.setAlias(args[++argindex]);
            } else if("--cn".equals(arg)) {
                cec.setCommonName(args[++argindex]);
            } else if("--report".equals(arg) || "-r".equals(arg)) {
                cec.out.println("Supported keystore types: " + cec.getSupportedKeystoreTypes(cec.provider, false));

                System.exit(0);
            } else if("--silent".equals(arg) || "-s".equals(arg)) {
                @SuppressWarnings("resource")
                PrintStream devNull = new PrintStream(new NullOutputStream(), false, Charset.defaultCharset().name());
                cec.out = devNull;
                cec.err = devNull;
            } else if("--quiet".equals(arg) || "-q".equals(arg)) {
                cec.quiet = true;
                cec.verbose = false; // Implied
            } else if("-o".equals(arg) || "--options".equals(arg)) {
                cec.loadOptionsFile(args[++argindex]);
            } else if("--".equals(arg)) {
                break;
            } else if("--help".equals(arg) || "-h".equals(arg)) {
                usage(cec.out);

                System.exit(0);
            } else {
                // Anything else is a filename
                status = status.max(cec.processFilename(arg));

                processedFile = true;
            }
        }

        int exitCode = 3; // UNKNOWN

        if(!processedFile) {
            cec.out.println("No file(s) specified.");
            cec.out.println();

            usage(cec.out);
        } else {
            status = status.max(cec.exec(args, argindex));

            if(Status.UNKNOWN == status) {
                cec.out.println("UNKNOWN: Processed zero certificates");

                exitCode = 3; // UNKNOWN

                if(cec.debug) {
                    cec.out.println("DEBUG: exiting with status=" + status + ", code=3");
                }
            } else if(Status.OK == status) {
                if(!cec.quiet) {
                    cec.out.println("OK: All certificates valid");
                }

                if(cec.debug) {
                    cec.out.println("DEBUG: exiting with status=" + status + ", code=0");
                }

                exitCode = 0; // OK
            } else {
                if(cec.debug) {
                    cec.out.println("DEBUG: exiting with status=" + status + ", code=" + (status.ordinal()-1));
                }
                exitCode = status.ordinal() - 1;
            }
        }

        System.exit(exitCode);
    }

    private static final String PEM_ENTRY_HEADER = "-----BEGIN";
    private static final byte[] PEM_ENTRY_HEADER_BYTES = PEM_ENTRY_HEADER.getBytes(StandardCharsets.US_ASCII);

    private boolean debug = false;
    private boolean verbose = false;
    private boolean quiet = false;
    private DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    private String keystorePassword = "changeit";
    private String alias;
    private String commonName;
    private int warnDays = 45;
    private int critDays = 30;
    private int maxDays = -1; // Any number of days is okay
    private Provider provider = null; // Default == whoever wants to provide
    private Collection<String> keystoreTypes;
    private PrintStream out = System.out;
    private PrintStream err = System.err;

    public void setAlias(String alias) {
        if("".equals(alias)) {
            alias = null;
        }

        this.alias = alias;
    }

    public void setCommonName(String commonName) {
        if("".equals(commonName)) {
            commonName = null;
        }

        this.commonName = commonName;
    }

    public void setKeystorePassword(String password) {
        this.keystorePassword = password;
    }

    public void loadOptionsFile(String file) throws IOException {
        Properties props = new Properties();
        try(FileInputStream fin = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fin)) {
            props.load(bis);
        }
        if(props.containsKey("password")) {
            setKeystorePassword(props.getProperty("password"));
        }
    }

    public void init() {
        if(null == keystoreTypes) {
            keystoreTypes = getSupportedKeystoreTypes(provider, true);
        }
    }

    public Status checkSpecial(String keystoreType) throws IOException, GeneralSecurityException {
        init();

        Status status = Status.UNKNOWN;

        try {
            KeyStore ks = KeyStore.getInstance(keystoreType);
            ks.load(null, keystorePassword.toCharArray());
            status = status.max(process(new KeyStoreGenerator("Special:" + keystoreType, ks)));
        } catch (KeyStoreException kse) {
            err.println("ERROR: Failed to load keystore '" + keystoreType + "': " + kse.getMessage());
            status = status.max(Status.ERROR);
        }

        return status;
    }

    public Status exec(String[] args, int argindex) throws IOException, GeneralSecurityException {
        init();

        Status status = Status.UNKNOWN;
        if(debug) {
            out.println("DEBUG: Beginning exec(); argindex=" + argindex + ", args.length=" + args.length);
        }
        for(int i=argindex; i<args.length; ++i) {
            try {
                status = status.max(processFilename(args[i]));
            } catch (Exception e) {
                err.println("ERROR: " + e.getMessage());
                e.printStackTrace();

                status = Status.ERROR;
            }
        }

        if(debug) {
            out.println("DEBUG: Final status: " + status);
        }

        return status;
    }

    public enum Status {
        UNKNOWN,
        OK,
        WARN,
        CRITICAL,
        ERROR
        ;

        public Status max(Status status) {
            if(this.ordinal() > status.ordinal())
                return this;
            else
                return status;
        }
    }

    public Status processFilename(String filename) throws IOException {
        init();

        InputStream fin = null;

        try {
            fin = new BufferedInputStream(new FileInputStream(filename));
            if(!fin.markSupported())
                throw new IOException("Cannot mark/rewind");

            // Sniff the input stream: is this a PEM file or is this a keystore?
            fin.mark(1024);

            byte[] header = new byte[1024];
            int count = fin.read(header);

            if(count < 1024) {
                throw new IOException("File " + filename + " is pretty tiny");
            }

            fin.reset();

            // Just for testing:
            //Security.setProperty("keystore.type.compat", "false");

            DescriptorGenerator generator;

            if(-1 < KMP.indexOf(header, PEM_ENTRY_HEADER_BYTES)) {
                // File is PEM file
                generator = new PEMFileGenerator(filename, fin);
            } else {
                // Maybe this is a KeyStore
                KeyStore ks = loadArbitraryKeystoreFile(filename, fin, keystorePassword, provider, keystoreTypes);

                if(null != ks) {
                    generator = new KeyStoreGenerator(filename, ks);
                } else {
                    generator = null;
                }
            }

            if(null == generator) {
                err.println("ERROR: Unable to open file " + filename);

                return Status.ERROR;
            }

            return process(generator);
        } finally {
            if(null != fin) try { fin.close(); } catch (IOException ioe)
            { err.println("Cannot close file " + filename); }
        }
    }

    public Status process(DescriptorGenerator generator) {
        Status status = Status.UNKNOWN;

        boolean processedCert = false;
        if(debug) {
           out.println("DEBUG: Beginning process() on generator " + generator);
        }
        for(Descriptor descriptor : generator) {
            if(null != alias && !alias.equals(descriptor.alias)) {
                continue;
            }

            Certificate cert = descriptor.cert;
            if(null != cert) {
                if("X.509".equals(cert.getType())) {
                    X509Certificate x509 = (X509Certificate)cert;

                    if(null != commonName && !commonName.equals(x509.getSubjectX500Principal().getName())) {
                        continue;
                    }

                    processedCert = true;
                    Date date = x509.getNotBefore();
                    if(null == date) {
                        err.println("ERROR: " + descriptor + ": missing not-before date");

                        status = status.max(Status.ERROR);

                        continue;
                    }
                    Date now = new Date();
                    if(now.before(date)) {
                        err.println("CRITICAL: " + descriptor + ": certificate is not yet valid");

                        status = status.max(Status.CRITICAL);

                        continue;
                    }
                    date = x509.getNotAfter();
                    if(null == date) {
                        err.println("ERROR: " + descriptor + ": missing not-after date");

                        status = status.max(Status.ERROR);

                        continue;
                    }
                    if(now.after(date)) {
                        err.println("CRITICAL: " + descriptor + ": certificate has expired (" + df.format(date) + ")");

                        status = status.max(Status.CRITICAL);

                        continue;
                    }

                    long expirationDays = Duration.between(now.toInstant(), date.toInstant()).toDays();
                    if(expirationDays < critDays) {
                        err.println("CRITICAL: " + descriptor + ": expires in " + expirationDays + " days");

                        status = status.max(Status.CRITICAL);

                        continue;
                    } else if(expirationDays < warnDays) {
                        err.println("WARN: " + descriptor + ": expires in " + expirationDays + " days");

                        status = status.max(Status.WARN);

                        continue;
                    } else if(maxDays > -1 && expirationDays > maxDays) {
                        err.println("WARN: " + descriptor + ": expires in " + expirationDays + " days");

                        status = status.max(Status.WARN);
                    }

                    if(verbose) {
                        out.println("OK: " + descriptor + " expires in " + expirationDays + " days (" + df.format(date) + ")");
                    }
                    status = status.max(Status.OK);
                } else {
                    err.println("ERROR: Unknown certificate type: " + cert.getType());

                    status = status.max(Status.ERROR);
                }
            }
        }

        if(!processedCert) {
            if(null != alias && null != commonName) {
                err.println("UNKNOWN: Found no certficiate with alias '" + alias + "' and commons name '" + commonName + "' in " + generator.getFilename());
            } else if(null != alias) {
                err.println("UNKNOWN: Found no certficiate with alias '" + alias + "' in " + generator.getFilename());
            } else if(null != commonName) {
                err.println("UNKNOWN: Found no certficiate with common name '" + commonName + "' in " + generator.getFilename());
            }

            status = status.max(Status.UNKNOWN);
        }
        if(debug) {
           out.println("DEBUG: Completing process() on generator " + generator + ", final status=" + status);
        }
        return status;
    }

    private KeyStore loadArbitraryKeystoreFile(String filename, InputStream in, String keystorePassword, Provider provider, Collection<String> keystoreTypes)
        throws IOException
    {
        if(!in.markSupported()) {
            throw new IllegalArgumentException("Can't work with a non-rewindable InputStream; sorry");
        }

        KeyStore ks;

        in.mark(1024); // Arbitrary marker

        for(String type : keystoreTypes) {
            try {
                if(debug) {
                    out.println("DEBUG: Attempting to load " + filename + " as a " + type + " keystore");
                }

                if(null != provider) {
                    ks = KeyStore.getInstance(type, provider);
                } else {
                    ks = KeyStore.getInstance(type);
                }

                in.reset(); // Re-wind if necessary

                // At least one keystore implementation calls InputStream.close() on the passed-in InputStream
                if(null != keystorePassword) {
                    ks.load(new UnclosableInputStream(type, in), keystorePassword.toCharArray());
                } else {
                    ks.load(new UnclosableInputStream(type, in), null);
                }

                return ks;
            } catch (IOException ioe) {
                if(ioe.getCause() instanceof UnrecoverableKeyException) {
                    // Invalid keystore password; in any case, we can't load it
                    if(debug) {
                        out.println("DEBUG: Incorrect password for keystore " + filename);
                    }
                    return null;
                }
                // Craptacular error-discovery :(
                if("Invalid keystore format".equals(ioe.getMessage())) {
                    if(debug) {
                        out.println("DEBUG: Failed to load " + filename + " as a " + type + " keystore: " + ioe.getMessage());
                    }
                } else {
                    throw ioe;
                }
            } catch (KeyStoreException kse) {
                if(debug) {
                    out.println("DEBUG: Failed to load " + filename + " as a " + type + " keystore: " + kse.getMessage());
                }
            } catch (NoSuchAlgorithmException nsae) {
                if(debug) {
                    out.println("DEBUG: Failed to load " + filename + " as a " + type + " keystore: " + nsae.getMessage());
                }
            } catch (CertificateException ce) {
                if(debug) {
                    out.println("DEBUG: Failed to load " + filename + " as a " + type + " keystore: " + ce.getMessage());
                }
            }
        }

        return null;
    }

    /**
     * Discovers which keystore types are available from the Java Runtime Environment.
     *
     * This implementation specifically ignores the following keystore types:
     * <code>DKS</code> (this is a meta-keystore type),
     * <code>KeychainStore</code> (this is an OS-provided keystore),
     * <code>Windows-ROOT</code> (this is an OS-provided keystore),
     * <code>Windows-MY</code> (this is an OS-provided keystore).
     *
     * @param provider A Provider to only detect keystore formats supported by
     *                 a specific crypto provider, or <code>null</code> to
     *                 detect support for all available crypto providers.
     *
     * @return A Collection of supported keystore formats.
     */
    private Collection<String> getSupportedKeystoreTypes(Provider provider, boolean filter) {
        Provider[] providers;
        if(null == provider) {
            providers = Security.getProviders();
        } else {
            providers = new Provider[] { provider };
        }
        Collection<String> types = new TreeSet<String>(); // TreeSet for sorting

        for(Provider p : providers) {
            Collection<Object> keys = p.keySet();
            for(Object key : keys) {
                if(key instanceof String) {
                    if(((String)key).startsWith("KeyStore.")) {
                        String type = ((String)key).substring(9);
                        if(!type.contains(" ")
                           && !"DKS".equals(type) // DKS needs some weird type of load parameters
                           && (!filter ||
                             (!"KeychainStore".equals(type) // Keychain is the Macos user keystore
                             && !"!Windows-MY".equals(type) // Windows-MY is the Windows user keystore
                             && !"!Windows-ROOT".equals(type) // Windows-ROOT is the Windows global keystore
                           )))
                        {
                            types.add(type);
                        }
                    }
                }
            }
        }

        // If we have our choice, use CaseExactJKS to avoid any problems with colliding aliases
        if(!filter && types.contains("CaseExactJKS") && types.contains("JKS")) {
            if(debug) {
                out.println("DEBUG: Removing 'JKS' in favor of 'CaseExactJKS' keystore type");
            }
            types.remove("JKS");
        }

        if(debug) {
            if(null == provider) {
                out.println("DEBUG: Determined available keystore types: " + types);
            } else {
                out.println("DEBUG: Determined available keystore types for provider '" + provider.getName() + ": " + types);
            }
        }

        return types;
    }

    /**
     * A certificate and some metadata.
     */
    static class Descriptor {
        String filename;
        String alias;
        Certificate cert;

        Descriptor(String filename, String alias, Certificate cert) {
            this.filename = filename;
            this.alias = alias;
            this.cert = cert;
        }

        @Override
        public String toString() {
            return filename + "::"  + alias;
        }
    }

    /**
     * An interface indicating that a class can produce
     * an iterator of {@link Descriptor} objects.
     */
    interface DescriptorGenerator extends Iterable<Descriptor>
    {
        public String getFilename();
    }

    /**
     * A class that produces a stream of Descriptor objects
     * from a PEM file.
     */
    class PEMFileGenerator implements DescriptorGenerator
    {
        String filename;
        Collection<? extends Certificate> certs;

        public PEMFileGenerator(String filename, InputStream in) {
            this.filename = filename;
            try {
                certs = CertificateFactory.getInstance("X.509").generateCertificates(in);

                if(debug) {
                    out.println("DEBUG: Loaded " + certs.size() + " from PEM file " + filename);
                }
            } catch (CertificateException ce) {
                throw new IllegalStateException("Could not parse PEM file", ce);
            }
        }

        @Override
        public String getFilename() {
            return filename;
        }

        @Override
        public Iterator<Descriptor> iterator() {
            return new Walker();
        }

        private class Walker implements Iterator<Descriptor> {
            private Iterator<? extends Certificate> i;

            public Walker() {
                i = certs.iterator();
            }
            @Override
            public boolean hasNext() {
                return i.hasNext();
            }

            @Override
            public Descriptor next() {
                Certificate cert = i.next();

                if("X.509".equals(cert.getType())) {
                    return new Descriptor(filename, ((X509Certificate)cert).getSubjectDN().getName(), cert);
                } else {
                    return new Descriptor(filename, cert.getType() + ":??", cert);
                }
            }
        }
    }

    /**
     * A class that produces a stream of Descriptor objects
     * from a keystore.
     */
    class KeyStoreGenerator implements DescriptorGenerator
    {
        String filename;
        KeyStore keystore;

        public KeyStoreGenerator(String filename, KeyStore ks) {
            this.filename = filename;
            keystore = ks;
            try {
                if(debug) {
                    out.println("DEBUG: Loaded " + ks.size() + " from " + keystore.getType() + " keystore file " + filename);
                }
            } catch (KeyStoreException kse) {
                throw new IllegalStateException("Could not enumerate KeyStore aliases", kse);
            }
        }

        @Override
        public String getFilename() {
            return filename;
        }

        @Override
        public Iterator<Descriptor> iterator() {
            try {
                return new Walker();
            } catch (KeyStoreException kse) {
                throw new IllegalStateException("Cannot read KeyStore", kse);
            }
        }

        private class Walker implements Iterator<Descriptor> {
            Enumeration<String> aliases;
            private Walker() throws KeyStoreException {
                aliases = keystore.aliases();
            }

            @Override
            public boolean hasNext() {
                return aliases.hasMoreElements();
            }

            @Override
            public Descriptor next() {
                String alias = aliases.nextElement();

                // It's stupid, but we have to try to load the entry and fail
                // in order to try with a password. Trying with a password
                // for a non-protected entry throws a different kind of exception :(
                KeyStore.Entry entry;
                try {
                    try {
                        entry = keystore.getEntry(alias, null);
                    } catch (UnrecoverableKeyException uke) {
                        entry = keystore.getEntry(alias, new KeyStore.PasswordProtection(keystorePassword.toCharArray()));
                    }
                } catch (NoSuchAlgorithmException nsae) {
                    throw new IllegalStateException("Cannot get next KeyStore entry", nsae);
                } catch (UnrecoverableEntryException uee) {
                    throw new IllegalStateException("Cannot get next KeyStore entry", uee);
                } catch (KeyStoreException kse) {
                    throw new IllegalStateException("Cannot get next KeyStore entry", kse);
                }

                Certificate cert;
                if(entry instanceof KeyStore.PrivateKeyEntry) {
                    cert = ((KeyStore.PrivateKeyEntry)entry).getCertificate();
                } else if(entry instanceof KeyStore.SecretKeyEntry) {
                    cert = null;
                } else if(entry instanceof KeyStore.TrustedCertificateEntry) {
                    cert = ((KeyStore.TrustedCertificateEntry)entry).getTrustedCertificate();
                } else {
                    cert = null;
                }

                return new Descriptor(filename, alias, cert);
            }

        }
    }

    private class UnclosableInputStream
        extends java.io.FilterInputStream
    {
        String keystoreType;
        protected UnclosableInputStream(String keystoreType, InputStream in) {
            super(in);

            this.keystoreType = keystoreType;
        }

        @Override
        public void close() throws IOException
        {
            if(debug) {
                out.println("DEBUG: Ignoring attempt to close InputStream by provider of keystore type " + keystoreType);
                //new Throwable("trace").printStackTrace();
            }
        }
    }

    private static class NullOutputStream
        extends java.io.OutputStream
    {
        @Override
        public void write(int b) throws java.io.IOException
        {
            // Swallow output
        }
    }
}
