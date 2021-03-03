package com.horizen.librustsidechains;

import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.io.*;
import java.net.URL;

public class Library {

    private static boolean loaded = false;

    private static String tempDirName = "zendoo_lib";

    private static String commonLibName = "zendoo_sc";

    private static String windowsOsName = "windows";
    private static String linuxOsName = "linux";
    private static String osxOsName = "osx";

    private static String windowsLibName = commonLibName + ".dll";
    private static String linuxLibName = "lib" + commonLibName + ".so";
    private static String osxLibName = commonLibName + ".jnilib";

    // Order is important: dependencies first
    private static List<String> windowsDependenciesLibNames = Arrays.asList("libwinpthread-1.dll", "libgcc_s_seh-1.dll", "libstdc++-6.dll");

    static {
        load();
    }

    private static String getOperatingSystem() {
        String name = System.getProperty("os.name").toLowerCase().trim();
        if( name.startsWith("linux") ) {
            return linuxOsName;
        }
        if( name.startsWith("mac os x") ) {
            return osxOsName;
        }
        if( name.startsWith("win") ) {
            return windowsOsName;
        }
        return name;
    }

    private static int getModel() {
        String model = System.getProperty("sun.arch.data.model");
        if (model == null) {
            model = System.getProperty("com.ibm.vm.bitmode");
        }
        if (model!=null) {
            return Integer.parseInt(model);
        }
        return -1;
    }

    private static List<String> getLibNames() {
        String osName = getOperatingSystem();
        if (osName.equalsIgnoreCase(windowsOsName)) {
            ArrayList<String> res = new ArrayList<>(windowsDependenciesLibNames);
            res.add(windowsLibName);
            return res;
        }
        if (osName.equalsIgnoreCase(linuxOsName)) {
            return Collections.singletonList(linuxLibName);
        }
        if (osName.equalsIgnoreCase(osxOsName)) {
            return Collections.singletonList(osxLibName);
        }
        throw new IllegalArgumentException("Unsupported operation system: no libs defined.");
    }

    private static URL getResource(String libName) {
        String resourcePath = "native/" + getOperatingSystem() + getModel() + "/" + libName;
        return Library.class.getClassLoader().getResource(resourcePath);
    }


    private static File createTempDirectory(String prefix) throws IOException {
        String tempDir = System.getProperty("java.io.tmpdir");
        File generatedDir = new File(tempDir, prefix + System.nanoTime());

        if (!generatedDir.mkdir())
            throw new IOException("Failed to create temp directory " + generatedDir.getName());

        return generatedDir;
    }

    private static void extractLoad() {
        List<String> libNames = getLibNames();

        try {
            File temporaryDir = createTempDirectory(tempDirName);
            temporaryDir.deleteOnExit();

            for (String libName : libNames) {
                try(InputStream is = getResource(libName).openStream()) {
                    File targetFile = new File(temporaryDir, libName);
                    targetFile.deleteOnExit();
                    Files.copy(is, targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    System.load(targetFile.getAbsolutePath());
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static synchronized void load() {
        if (!loaded) {
            extractLoad();
            loaded = true;
        }
    }

}