from xml.sax import make_parser

from django.utils import timezone

from .utils import upload_file
from .utils import read_file
from .utils import time_string_to_datetime

from .handlers import CAPECHandler

from .models import VULNERABILITY_CAPEC
from .models import VULNERABILITY_CAPEC_NEW
from .models import VULNERABILITY_CAPEC_MODIFIED
from .models import STATUS_CAPEC

from .configurations import CAPECConfig

from .text_messages import TextMessages

import logging
logger = logging.getLogger(__name__)


def print_debug(message):
	if CAPECConfig.debug:
		print(message)


def pack_answer(
		status=TextMessages.error.value,
		message=TextMessages.error.value,
		capec_cnt_before=0,
		capec_cnt_after=0,
		new_cnt=0,
		modified_cnt=0
):
	return dict(
		vulnerability=dict(
			count_before=capec_cnt_before,
			count_after=capec_cnt_after),
		vulnerability_new=dict(
			count=new_cnt),
		vulnerability_modified=dict(
			count=modified_cnt),
		status=status,
		message=message
	)


class CAPECController(object):

	@staticmethod
	def clear_vulneranility_capec_table():
		for x in VULNERABILITY_CAPEC.objects.all().iterator():
			x.delete()

	@staticmethod
	def clear_vulnerability_capec_new_table():
		for x in VULNERABILITY_CAPEC_NEW.objects.all().iterator():
			x.delete()

	@staticmethod
	def clear_vulnerability_capec_modified_table():
		for x in VULNERABILITY_CAPEC_MODIFIED.objects.all().iterator():
			x.delete()

	@staticmethod
	def count_vulnerability_capec_table():
		return VULNERABILITY_CAPEC.objects.count()

	@staticmethod
	def count_vulnerability_capec_new_tabele():
		return VULNERABILITY_CAPEC_NEW.objects.count()

	@staticmethod
	def count_vulnerability_capec_modified_table():
		return VULNERABILITY_CAPEC_MODIFIED.objects.count()

	@staticmethod
	def append_capec_in_vulnerability_capec_table(capec: dict):
		return VULNERABILITY_CAPEC.objects.create(
			capec_id=capec["capec_id"],
			name=capec["name"],
			summary=capec["summary"],
			prerequisites=capec["prerequisites"],
			solutions=capec["solutions"],
			related_weakness=capec["related_weakness"]
		)

	@staticmethod
	def append_capec_in_vulnerability_capec_new_table(capec: dict):
		objects = VULNERABILITY_CAPEC_NEW.objects.filter(capec_id=capec['capec_id'])
		if len(objects) == 0:
			return VULNERABILITY_CAPEC_NEW.objects.create(
				capec_id=capec["capec_id"],
				name=capec["name"],
				summary=capec["summary"],
				prerequisites=capec["prerequisites"],
				solutions=capec["solutions"],
				related_weakness=capec["related_weakness"]
			)

	@staticmethod
	def append_capec_in_vulnerability_capec_modified_table(capec: dict):
		objects = VULNERABILITY_CAPEC_MODIFIED.objects.filter(capec_id=capec['capec_id'])
		if len(objects) == 0:
			return VULNERABILITY_CAPEC_MODIFIED.objects.create(
				capec_id=capec["capec_id"],
				name=capec["name"],
				summary=capec["summary"],
				prerequisites=capec["prerequisites"],
				solutions=capec["solutions"],
				related_weakness=capec["related_weakness"]
			)

	@staticmethod
	def save_status_in_local_status_table(status: dict):
		obj = STATUS_CAPEC.objects.filter(name="capec")
		if obj:
			return STATUS_CAPEC.objects.filter(name="capec").update(
				count=status.get("count", 0),
				updated=status.get("updated", timezone.now())
			)
		return STATUS_CAPEC.objects.create(
			name="capec",
			count=status.get("count", 0),
			created=timezone.now(),
			updated=status.get("updated", timezone.now())
		)

	@staticmethod
	def get_status_from_local_status_table() -> dict:
		obj = STATUS_CAPEC.objects.filter(name="capec")
		if obj:
			return obj.data
		return dict(
			exists=False,
			count=0,
			created=timezone.now(),
			updated=timezone.now()
		)

	@staticmethod
	def save_status_in_global_status_table(status: dict):
		pass

	@staticmethod
	def get_status_from_global_status_table() -> dict:
		pass

	@staticmethod
	def check_if_capec_item_changed(old: dict, new: dict):
		if old["name"] != new["name"] or \
			old["summary"] != new["summary"] or \
			old["prerequisites"] != new["prerequisites"] or \
			old["solutions"] != new["solutions"] or\
			old["related_weakness"] != new["related_weakness"]:
			return True
		return False

	@staticmethod
	def update_capec_in_capec_table(capec: dict):
		return VULNERABILITY_CAPEC.objects.filter(capec_id=capec["capec_id"]).update(
			name=capec["name"],
			summary=capec["summary"],
			prerequisites=capec["prerequisites"],
			solutions=capec["solutions"],
			related_weakness=capec["related_weakness"]
		)

	def create_or_update_capec_vulnertability(self, capec: dict):
		objects = VULNERABILITY_CAPEC.objects.filter(capec_id=capec['capec_id'])
		if len(objects) == 0:
			self.append_capec_in_vulnerability_capec_table(capec)
			self.append_capec_in_vulnerability_capec_new_table(capec)
		else:
			o = objects[0].data
			if self.check_if_capec_item_changed(o, capec):
				self.update_capec_in_capec_table(capec)
				self.append_capec_in_vulnerability_capec_modified_table(capec)

	def stats(self):
		return pack_answer(
			status=TextMessages.ok.value,
			message=TextMessages.ok.value,
			capec_cnt_before=self.count_vulnerability_capec_table(),
			capec_cnt_after=self.count_vulnerability_capec_table(),
			new_cnt=self.count_vulnerability_capec_new_tabele(),
			modified_cnt=self.count_vulnerability_capec_modified_table()
		)

	def update(self):
		if CAPECConfig.drop_core_table:
			self.clear_vulneranility_capec_table()
		self.clear_vulnerability_capec_new_table()
		self.clear_vulnerability_capec_modified_table()
		count_before = count_after = self.count_vulnerability_capec_table()
		parser = make_parser()
		capec_handler = CAPECHandler()
		parser.setContentHandler(capec_handler)
		(file_path, success, last_modified, size, fmt) = upload_file()
		if success and file_path != '':
			# FIXME: Make last_modified comparison
			(f, success, message) = read_file(file_path)
			if f is None or not success:
				return pack_answer(
					status=TextMessages.exception.value,
					message=message,
					capec_cnt_before=count_before,
					capec_cnt_after=count_after,
					new_cnt=0,
					modified_cnt=0
				)
			logger.info(TextMessages.parse_data.value)
			parser.parse(f)

			count = 0
			for capec in capec_handler.capec:
				print_debug('processing: {}'.format(count))
				count += 1
				capec['capec_id'] = 'CAPEC-{}'.format(capec['id'])
				related_weakness = capec.get("related_weakness", [])
				if related_weakness:
					for index, value in related_weakness:
						related_weakness[index] = "CWE-{}".format(value)
				capec["related_weakness"] = related_weakness

				self.create_or_update_capec_vulnertability(capec)

			count_after = self.count_vulnerability_capec_table()

			self.save_status_in_local_status_table(dict(
				count=count_after,
				updated=time_string_to_datetime(last_modified)
			))

			return pack_answer(
				status=TextMessages.ok.value,
				message=TextMessages.capec_updated.value,
				capec_cnt_before=count_before,
				capec_cnt_after=count_after,
				new_cnt=self.count_vulnerability_capec_new_tabele(),
				modified_cnt=self.count_vulnerability_capec_modified_table()
			)
		return pack_answer(
			status=TextMessages.error.value,
			message=TextMessages.cant_download_file.value,
			capec_cnt_before=count_before,
			capec_cnt_after=count_after,
			new_cnt=0,
			modified_cnt=0
		)
