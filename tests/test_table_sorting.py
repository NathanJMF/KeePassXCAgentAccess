"""Exercise the ordering used by the Keeper workspace tables."""

from types import SimpleNamespace
from unittest import TestCase

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from keepassxc_agent_access.owner_views import _time
from keepassxc_agent_access.workspace_views import TableSort, sorted_table_rows, table_time


class Header:
    def __init__(self):
        self.indicator = False
        self.sort_order = None

    def set_sort_indicator(self, shown):
        self.indicator = shown

    def set_sort_order(self, order):
        self.sort_order = order


class TableSortingTests(TestCase):
    def test_case_insensitive_order_is_stable_and_blanks_stay_last(self):
        default = [("Zulu", "1"), ("", "2"), ("alpha", "3"), ("Alpha", "4"), ("—", "5")]
        ascending = [default[i] for i in (2, 3, 0, 1, 4)]
        descending = [default[i] for i in (0, 2, 3, 1, 4)]
        self.assertEqual(sorted_table_rows(default, 0), ascending)
        self.assertEqual(sorted_table_rows(default, 0, descending=True), descending)

    def test_sorting_within_review_groups_preserves_default_priority(self):
        default = [("Zed", False), ("Alpha", False), ("Amelia", True), ("Jules", True)]
        self.assertEqual(sorted_table_rows(default, 0, group_column=1),
                         [default[i] for i in (1, 0, 2, 3)])
        self.assertEqual(sorted_table_rows(default, 0, descending=True, group_column=1),
                         [default[i] for i in (0, 1, 3, 2)])

    def test_time_keys_sort_chronologically_and_missing_times_stay_last(self):
        newer, older = 1_893_542_400.0, 1_893_456_000.0
        default = [(table_time(newer), newer), ("—", None), (table_time(older), older)]
        self.assertEqual(sorted_table_rows(default, 1), [default[2], default[0], default[1]])
        self.assertEqual(sorted_table_rows(default, 1, descending=True), [default[0], default[2], default[1]])

    def test_epoch_zero_is_a_real_timestamp_in_one_or_both_formats(self):
        self.assertNotEqual(table_time(0), "—")
        self.assertNotEqual(table_time(0, include_year=True), "—")
        self.assertNotEqual(_time(0), "—")
        self.assertEqual(table_time(None, include_year=True), "—")
        self.assertEqual(_time(None), "—")

    def test_click_cycles_sort_arrows_and_restores_row_order(self):
        date, name = Header(), Header()
        table = SimpleNamespace(get_columns=lambda: [name, date])
        sort = TableSort({0: 2}, None)
        default = [("Earlier label", "B", 3.5), ("Later label", "A", 1.2)]
        sort.rows = default
        sort.click(date, table, 0)
        self.assertTrue(date.indicator)
        self.assertEqual(date.sort_order, Gtk.SortType.ASCENDING)
        self.assertEqual(sort.visible_rows(), default[::-1])
        sort.click(date, table, 0)
        self.assertEqual(date.sort_order, Gtk.SortType.DESCENDING)
        self.assertEqual(sort.visible_rows(), default)

        sort.click(name, table, 1)
        self.assertFalse(date.indicator)
        self.assertTrue(name.indicator)
        self.assertEqual(name.sort_order, Gtk.SortType.ASCENDING)
        self.assertEqual(sort.visible_rows(), default[::-1])
        sort.click(name, table, 1)
        sort.click(name, table, 1)
        self.assertFalse(name.indicator)
        self.assertEqual(sort.visible_rows(), default)
