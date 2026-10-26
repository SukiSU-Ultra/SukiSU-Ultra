package com.sukisu.ultra.ui.util

import com.sukisu.ultra.data.registry.ExpectedFile
import com.sukisu.ultra.data.registry.RegistryDownloadStore
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files

class ModuleZipDeletionTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var filesDir: File
    private lateinit var cacheDir: File

    @Before
    fun setUp() {
        filesDir = tmp.newFolder("files")
        cacheDir = tmp.newFolder("cache")
    }

    private fun delete(
        scheme: String?,
        path: String?,
        isDocument: () -> Boolean = { false },
        deleteDocument: () -> Boolean = { throw AssertionError("deleteDocument must not run") },
        deleteRow: () -> Int = { throw AssertionError("deleteRow must not run") },
    ): Boolean = deleteModuleZip(scheme, path, filesDir, cacheDir, isDocument, deleteDocument, deleteRow)

    private fun zipIn(dir: File, name: String = "module.zip"): File =
        File(dir, name).apply {
            parentFile?.mkdirs()
            writeText("zip")
        }

    @Test
    fun registryDownloadIsDeletedWithItsDirectory() {
        val root = File(filesDir, RegistryDownloadStore.DIR_NAME).apply { mkdirs() }
        val dir = File(root, RegistryDownloadStore.dirNameFor(ExpectedFile(42L, "a".repeat(64)))).apply { mkdirs() }
        val zip = zipIn(dir)

        assertTrue(delete("file", zip.path))
        assertFalse(zip.exists())
        assertFalse(dir.exists())
    }

    @Test
    fun cacheCopyWithAwkwardNameIsDeleted() {
        val zip = zipIn(cacheDir, "my module's zip , _data=x\n.zip")

        assertTrue(delete("file", zip.path))
        assertFalse(zip.exists())
    }

    @Test
    fun fileOutsidePrivateDirectoriesIsKept() {
        val outside = zipIn(tmp.newFolder("outside"))
        val inFilesDir = zipIn(filesDir)

        assertFalse(delete("file", outside.path))
        assertTrue(outside.exists())
        assertFalse(delete("file", inFilesDir.path))
        assertTrue(inFilesDir.exists())
    }

    @Test
    fun pathTraversalOutOfCacheIsKept() {
        val outside = zipIn(tmp.newFolder("outside"))
        val path = File(cacheDir, "../outside/${outside.name}").path

        assertFalse(delete("file", path))
        assertTrue(outside.exists())
    }

    @Test
    fun symlinkOutOfCacheIsKept() {
        val outside = zipIn(tmp.newFolder("outside"))
        val link = File(cacheDir, "link.zip")
        try {
            Files.createSymbolicLink(link.toPath(), outside.toPath())
        } catch (e: Exception) {
            assumeNoException(e)
        }

        assertFalse(delete("file", link.path))
        assertTrue(outside.exists())
    }

    @Test
    fun missingOrRelativePathIsRejected() {
        assertFalse(delete("file", null))
        assertFalse(delete("file", "relative.zip"))
        assertFalse(delete("file", ""))
    }

    @Test
    fun unknownSchemeIsRejected() {
        assertFalse(delete("http", "/data/local/tmp/module.zip"))
    }

    @Test
    fun documentIsDeletedThroughItsProvider() {
        var deleted = false

        assertTrue(delete("content", null, isDocument = { true }, deleteDocument = { deleted = true; true }))
        assertTrue(deleted)
    }

    @Test
    fun providerReturningFalseIsNotReportedAsDeleted() {
        var askedToDelete = false

        assertFalse(delete("content", null, isDocument = { true }, deleteDocument = { askedToDelete = true; false }))
        assertTrue(askedToDelete)
    }

    @Test
    fun providerRefusalLeavesTheZipAlone() {
        assertFalse(
            delete(
                "content",
                null,
                isDocument = { true },
                deleteDocument = { throw UnsupportedOperationException("provider does not support delete") },
            )
        )
        assertFalse(
            delete(
                "content",
                null,
                isDocument = { false },
                deleteRow = { throw SecurityException("no access") },
            )
        )
    }

    @Test
    fun mediaDeleteNeedsADeletedRow() {
        assertFalse(delete("content", null, isDocument = { false }, deleteRow = { 0 }))
        assertTrue(delete("content", null, isDocument = { false }, deleteRow = { 1 }))
    }

    @Test
    fun malformedDocumentCheckIsRejectedWithoutThrowing() {
        assertFalse(delete("content", null, isDocument = { throw IllegalArgumentException("bad uri") }))
    }

    @Test
    fun deletionOnlyFollowsASuccessfulInstallWhenEnabled() {
        assertFalse(shouldDeleteSourceAfterInstall(enabled = false, installSucceeded = false))
        assertFalse(shouldDeleteSourceAfterInstall(enabled = false, installSucceeded = true))
        assertFalse(shouldDeleteSourceAfterInstall(enabled = true, installSucceeded = false))
        assertTrue(shouldDeleteSourceAfterInstall(enabled = true, installSucceeded = true))
    }
}
