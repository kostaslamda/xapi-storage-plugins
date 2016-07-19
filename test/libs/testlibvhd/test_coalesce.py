import mock
import unittest
from contextlib import contextmanager

from xapi.storage.libs.libvhd.metabase import VDI, VHD, Refresh, Journal
from xapi.storage.libs.libvhd import coalesce

@contextmanager
def test_context():
    yield

class VHDCoalesceTest(unittest.TestCase):

    # Tests for find non leaf coalesce

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_find_best_non_leaf_coalesce_no_results(self, mocklock, mocklog, mockMetabase):
        # Setup the mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.find_non_leaf_coalesceable.return_value = []

        # Call the method
        child, parent = coalesce.find_best_non_leaf_coalesceable_2("test-uri", callbacks)

        # Check the result
        self.assertEquals((None, None), (child, parent))

        # Check the calls
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        mockDB.write_context.assert_not_called()
        mockDB.update_vhd_gc_status.assert_not_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_find_best_non_leaf_coalesce_success(self, mocklock, mocklog, mockMetabase):
        # Setup the mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        mockDB.find_non_leaf_coalesceable.return_value = [
            VHD(
                3,
                2,
                0,
                10*1024,
                10*1024
                )
            ]
        mockDB.get_vhd_by_id.side_effect = [
            VHD(
                2,
                1,
                0,
                10*1024,
                10*1024
                )
            ]
        callbacks.volumeTryLock.side_effect = [ mock.MagicMock(), mock.MagicMock() ]

        # Call the method
        child, parent = coalesce.find_best_non_leaf_coalesceable_2("test-uri", callbacks)

        # Check the result
        self.assertEquals(3, child.vhd.id)
        self.assertEquals(2, parent.vhd.id)

        # Check the calls
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeTryLock.assert_has_calls(
            [mock.call(mock.ANY, "vhd-2.lock"), mock.call(mock.ANY, "vhd-3.lock")], any_order=True)
        self.assertEquals(2, callbacks.volumeTryLock.call_count)
        callbacks.volumeUnlock.assert_not_called()
        mockDB.update_vhd_gc_status.assert_not_called()
        mockDB.write_context.assert_called()
        self.assertEquals(1, mockDB.get_vhd_by_id.call_count)
        mockDB.get_vhd_by_id.assert_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_find_best_non_leaf_coalesce_parent_coalescing(self, mocklock, mocklog, mockMetabase):
        # Setup the mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        mockDB.find_non_leaf_coalesceable.return_value = [
            VHD(
                3,
                2,
                0,
                10*1024,
                10*1024
                )
            ]
        callbacks.volumeTryLock.side_effect = [ None ]

        # Call the method
        child, parent = coalesce.find_best_non_leaf_coalesceable_2("test-uri", callbacks)

        # Check the result
        self.assertEquals((None, None), (child, parent))

        # Check the calls
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeTryLock.assert_has_call(mock.ANY, "vhd-2.lock")
        self.assertEquals(1, callbacks.volumeTryLock.call_count)
        callbacks.volumeUnlock.assert_not_called()
        mockDB.write_context.assert_not_called()
        mockDB.update_vhd_gc_status.assert_not_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_find_best_non_leaf_coalesce_node_coalescing(self, mocklock, mocklog, mockMetabase):
        # Setup the mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        mockDB.find_non_leaf_coalesceable.return_value = [
            VHD(
                3,
                2,
                0,
                10*1024,
                10*1024
                )
            ]
        mockDB.get_vhd_by_id.side_effect = [
            VHD(
                2,
                1,
                0,
                10*1024,
                10*1024)
            ]
        parent_lock = mock.MagicMock()
        callbacks.volumeTryLock.side_effect = [ parent_lock, None ]

        # Call the method
        child, parent = coalesce.find_best_non_leaf_coalesceable_2("test-uri", callbacks)

        # Check the result
        self.assertEquals((None, None), (child, parent))

        # Check the calls
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeTryLock.assert_has_calls(
            [mock.call(mock.ANY, "vhd-2.lock"), mock.call(mock.ANY, "vhd-3.lock")], any_order=True)
        self.assertEquals(2, callbacks.volumeTryLock.call_count)
        callbacks.volumeUnlock.assert_has_call(mock.call(mock.ANY, parent_lock))
        self.assertEquals(1, callbacks.volumeUnlock.call_count)
        mockDB.write_context.assert_not_called()
        mockDB.get_vhd_by_id.assert_not_called()
        mockDB.update_vhd_gc_status.assert_not_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_find_best_non_leaf_coalesce_one_coalescing_success(self, mocklock, mocklog, mockMetabase):
        # Setup the mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        mockDB.find_non_leaf_coalesceable.return_value = [
            VHD(
                3,
                2,
                0,
                10*1024,
                10*1024),
            VHD(
                5,
                4,
                0,
                10*1024,
                10*1024
                )
            ]
        mockDB.get_vhd_by_id.side_effect = [
            VHD(
                4,
                1,
                0,
                10*1024,
                10*1024
                )
            ]

        parent_lock = mock.MagicMock()
        callbacks.volumeTryLock.side_effect = [ parent_lock, None, mock.MagicMock(), mock.MagicMock() ]

        # Call the method
        child, parent = coalesce.find_best_non_leaf_coalesceable_2("test-uri", callbacks)

        # Check the result
        self.assertEquals(5, child.vhd.id)
        self.assertEquals(4, parent.vhd.id)

        # Check the calls
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeTryLock.assert_has_calls(
            [
                mock.call(mock.ANY, "vhd-2.lock"),
                mock.call(mock.ANY, "vhd-3.lock"),
                mock.call(mock.ANY, "vhd-5.lock"),
                mock.call(mock.ANY, "vhd-4.lock"),
                ],
            any_order=True)
        self.assertEquals(4, callbacks.volumeTryLock.call_count)
        callbacks.volumeUnlock.assert_has_call(mock.call(mock.ANY, parent_lock))
        self.assertEquals(1, callbacks.volumeUnlock.call_count)
        mockDB.write_context.assert_called()
        mockDB.get_vhd_by_id.assert_called()
        mockDB.update_vhd_gc_status.assert_not_called()

    # Tests for non-leaf coalesce

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDUtil.set_parent')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDUtil.coalesce')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.poolhelper')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_non_leaf_coalesce_success_non_active(
            self,
            mocklock,
            mocklog,
            mockPoolHelper,
            mock_vhdutil_coalesce,
            mock_vhdutil_set_parent,
            mockMetabase):
        # Parameters for method in test
        node_lock = mock.MagicMock()
        node = coalesce.VhdLock(
            VHD(
                3,
                2,
                0,
                10*1024,
                10*1024
                ),
            node_lock)

        parent_lock = mock.MagicMock()
        parent = coalesce.VhdLock(
            VHD(
                2,
                1,
                0,
                10*1024,
                10*1024
                ),
            parent_lock)

        # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        # This is the leaf VHD
        leaf_vhd = VHD(
                    4,
                    3,
                    0,
                    10*1024,
                    10*1024
                    )
        mockDB.get_children.side_effect = [
                [leaf_vhd],
                []
            ]
        mockDB.get_vhd_by_id.side_effect = [leaf_vhd]

        # This is the VDI for the leaf VHD
        mockDB.get_vdi_for_vhd.return_value = VDI("1", "VDI1", "", None, None, leaf_vhd)

        mockDB.add_refresh_entries.side_effect =  [
            [ Refresh(4, 4) ]
            ]
        mockDB.add_journal_entries.side_effect = [
            [ Journal(4, 3, 2) ]
            ]

        # Call the method
        coalesce.non_leaf_coalesce(node, parent, "test-uri", callbacks)

        # Assert that the methods we expect to be called were called
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeDestroy.assert_called()
        callbacks.volumeUnlock.assert_has_calls(
            [mock.call(mock.ANY, node_lock), mock.call(mock.ANY, parent_lock)],
            any_order = True)
        self.assertEquals(2, callbacks.volumeUnlock.call_count)
        mock_vhdutil_coalesce.assert_called()
        mock_vhdutil_set_parent.assert_called()
        mockDB.update_vhd_parent.assert_called_with(4, 2)
        mockDB.delete_vhd.assert_called_with(3)
        mockDB.update_vhd_gc_status.assert_not_called()
        mockDB.get_vhd_by_id.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.get_vhd_by_id.call_count)
        mockDB.add_journal_entries.assert_has_calls([mock.call(3, 2, [leaf_vhd])])
        self.assertEquals(1, mockDB.add_journal_entries.call_count)
        mockDB.add_refresh_entries.assert_has_calls([mock.call(4, [leaf_vhd])])
        self.assertEquals(1, mockDB.add_refresh_entries.call_count)
        mockDB.remove_journal_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_journal_entry.call_count)
        mockDB.remove_refresh_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_refresh_entry.call_count)
        # Node wasn't active so no need to refresh the datapath
        mockPoolHelper.suspend_datapath_on_host.assert_not_called()
        mockPoolHelper.resume_datapath_on_host.assert_not_called()
        mockPoolHelper.refresh_datapath_on_host.assert_not_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDUtil.set_parent')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDUtil.coalesce')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.poolhelper')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_non_leaf_coalesce_success_active(
            self,
            mocklock,
            mocklog,
            mockPoolHelper,
            mock_vhdutil_coalesce,
            mock_vhdutil_set_parent,
            mockMetabase):
        # Parameters for method in test
        node_lock = mock.MagicMock()
        node = coalesce.VhdLock(
            VHD(
                3,
                2,
                0,
                10*1024,
                10*1024
                ),
            node_lock)

        parent_lock = mock.MagicMock()
        parent = coalesce.VhdLock(
            VHD(
                2,
                1,
                0,
                10*1024,
                10*1024
                ),
            parent_lock)
        
        # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        # This is the leaf VHD
        leaf_vhd = VHD(
                    4,
                    3,
                    0,
                    10*1024,
                    10*1024
                    )
        mockDB.get_children.side_effect = [           
                [leaf_vhd],
                []
            ]
        mockDB.get_vhd_by_id.side_effect = [leaf_vhd]

        # This is the VDI for the leaf VHD, active on Host1
        mockDB.get_vdi_for_vhd.return_value = VDI("1", "VDI1", "", "Host1", None, leaf_vhd)

        mockDB.add_refresh_entries.side_effect =  [
            [ Refresh(4, 4) ]
            ]
        mockDB.add_journal_entries.side_effect = [
            [ Journal(4, 3, 2) ]
            ]

        # Call the method
        coalesce.non_leaf_coalesce(node, parent, "test-uri", callbacks)

        # Assert that the methods we expect to be called were called
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeDestroy.assert_called()
        callbacks.volumeUnlock.assert_has_calls(
            [mock.call(mock.ANY, node_lock), mock.call(mock.ANY, parent_lock)],
            any_order = True)
        self.assertEquals(2, callbacks.volumeUnlock.call_count)
        mock_vhdutil_coalesce.assert_called()
        mock_vhdutil_set_parent.assert_called()
        mockDB.update_vhd_parent.assert_called_with(4, 2)
        mockDB.delete_vhd.assert_called_with(3)
        mockDB.update_vhd_gc_status.assert_not_called()
        mockDB.get_vhd_by_id.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.get_vhd_by_id.call_count)
        mockDB.add_journal_entries.assert_has_calls([mock.call(3, 2, [leaf_vhd])])
        self.assertEquals(1, mockDB.add_journal_entries.call_count)
        mockDB.add_refresh_entries.assert_has_calls([mock.call(4, [leaf_vhd])])
        self.assertEquals(1, mockDB.add_refresh_entries.call_count)
        mockDB.remove_journal_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_journal_entry.call_count)
        mockDB.remove_refresh_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_refresh_entry.call_count)
        # Node was active so need to refresh the datapath on the correct host
        mockPoolHelper.suspend_datapath_on_host.assert_not_called()
        mockPoolHelper.resume_datapath_on_host.assert_not_called()
        mockPoolHelper.refresh_datapath_on_host.assert_called_with("GC", "Host1", mock.ANY, mock.ANY)

    # Tests for garbage clean up

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    def test_remove_garbage_vhds_none(self, mockMetabase):
        # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        mockDB.get_garbage_vhds.return_value = []

        # call the code
        coalesce.remove_garbage_vhds("test-uri", callbacks)

        # check the results
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeDestroy.assert_not_called()
        mockDB.get_garbage_vhds.assert_called()
        mockDB.delete_vhd.assert_not_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    def test_remove_garbage_vhds_two(self, mockMetabase):
        # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        mockDB.get_garbage_vhds.return_value = [
            VHD(
                4,
                3,
                0,
                10*1024,
                10*1024
                ),

            VHD(
                5,
                3,
                0,
                10*1024,
                10*1024
                )
            ]

        # call the code
        coalesce.remove_garbage_vhds("test-uri", callbacks)

        # check the results
        callbacks.volumeStartOperations.assert_called_with("test-uri", 'w')
        callbacks.volumeStopOperations.assert_called()
        callbacks.volumeDestroy.assert_has_calls(
            [mock.call(mock.ANY, str(4)),mock.call(mock.ANY, str(5))],
            any_order=True)
        self.assertEquals(2, callbacks.volumeDestroy.call_count)
        mockDB.get_garbage_vhds.assert_called()
        mockDB.delete_vhd.assert_has_calls(
            [mock.call(4), mock.call(5)],
            any_order=True)
        self.assertEquals(2, mockDB.delete_vhd.call_count)

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.poolhelper')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_recover_noop_success(self, mocklock, mockPoolHelper, mockMetabase):
         # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context

        mockDB.get_refresh_entries.side_effect = [ [] ]

        coalesce.recover_journal("test-uri", callbacks)

        self.assertEquals(1, mockDB.get_refresh_entries.call_count)
        mockPoolHelper.suspend_datapath_on_host.assert_not_called()
        mockPoolHelper.resume_datapath_on_host.assert_not_called()
        mockPoolHelper.refresh_datapath_on_host.assert_not_called()


    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.poolhelper')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_recover_one_refresh_active_success(
        self,
        mocklock,
        mocklog,
        mockPoolHelper,
        mockMetabase):

         # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context

        mockDB.get_refresh_entries.side_effect = [ [ Refresh(4, 4) ] ]

        # This is the leaf VHD
        leaf_vhd = VHD(
                    4,
                    3,
                    0,
                    10*1024,
                    10*1024
                    )

        # This is the VDI for the leaf VHD
        mockDB.get_vdi_for_vhd.return_value = VDI(
            "1", "VDI1", "", "Host1", None, leaf_vhd)

        coalesce.recover_journal("test-uri", callbacks)

        self.assertEquals(1, mockDB.get_refresh_entries.call_count)
        mockDB.remove_refresh_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_refresh_entry.call_count)
        mockPoolHelper.suspend_datapath_on_host.assert_not_called()
        mockPoolHelper.resume_datapath_on_host.assert_not_called()
        mockPoolHelper.refresh_datapath_on_host.assert_called_with("GC", "Host1", mock.ANY, mock.ANY)

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.poolhelper')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_recover_one_refresh_vdi_missing_success(
        self,
        mocklock,
        mocklog,
        mockPoolHelper,
        mockMetabase):

        """ This allows for a VDI to have been deleted in the period between
        a coalesce abort and the recovery operation picking up the pieces.
        """

         # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context

        mockDB.get_refresh_entries.side_effect = [ [ Refresh(4, 4) ] ]

        # This is the leaf VHD
        leaf_vhd = VHD(
                    4,
                    3,
                    0,
                    10*1024,
                    10*1024
                    )

        # This is the VDI for the leaf VHD
        mockDB.get_vdi_for_vhd.return_value = None

        coalesce.recover_journal("test-uri", callbacks)

        self.assertEquals(1, mockDB.get_refresh_entries.call_count)
        mockDB.remove_refresh_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_refresh_entry.call_count)
        mockPoolHelper.suspend_datapath_on_host.assert_not_called()
        mockPoolHelper.resume_datapath_on_host.assert_not_called()
        mockPoolHelper.refresh_datapath_on_host.assert_not_called()

    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDMetabase')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.VHDUtil.set_parent')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.poolhelper')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.log')
    @mock.patch('xapi.storage.libs.libvhd.coalesce.Lock')
    def test_recover_one_journal_success_active(
        self,
        mocklock,
            mocklog,
            mockPoolHelper,
            mock_vhdutil_set_parent,
            mockMetabase):

        # Setup some mocks
        callbacks = mock.MagicMock()
        mockDB = mock.MagicMock()
        mockMetabase.return_value = mockDB
        mockDB.write_context.side_effect = test_context
        # This is the leaf VHD
        leaf_vhd = VHD(
                    4,
                    3,
                    0,
                    10*1024,
                    10*1024
                    )

        mockDB.get_children.side_effect = [           
                [leaf_vhd],
                []
            ]
        mockDB.get_vhd_by_id.side_effect = [leaf_vhd]

        # This is the VDI for the leaf VHD
        mockDB.get_vdi_for_vhd.return_value = VDI("1", "VDI1", "", "Host1", None, leaf_vhd)

        mockDB.add_refresh_entries.side_effect =  [
            [ Refresh(4, 4) ]
            ]
        mockDB.get_journal_entries.side_effect = [ 
            [ Journal(4, 3, 2) ]
            ]

        coalesce.recover_journal("test-uri", callbacks)

        self.assertEquals(1, mockDB.get_journal_entries.call_count)
        mock_vhdutil_set_parent.assert_called()
        mockDB.update_vhd_parent.assert_called_with(4, 2)
        mockDB.add_refresh_entries.assert_has_calls([mock.call(4, [leaf_vhd])])
        self.assertEquals(1, mockDB.add_refresh_entries.call_count)
        mockDB.remove_journal_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_journal_entry.call_count)
        mockDB.remove_refresh_entry.assert_has_calls([mock.call(4)])
        self.assertEquals(1, mockDB.remove_refresh_entry.call_count)
        mockPoolHelper.suspend_datapath_on_host.assert_not_called()
        mockPoolHelper.resume_datapath_on_host.assert_not_called()
        mockPoolHelper.refresh_datapath_on_host.assert_called_with("GC", "Host1", mock.ANY, mock.ANY)
