#!/usr/bin/env python

import datetime
import utils
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, Table, Text, DateTime, Enum
from sqlalchemy.orm import relationship, state
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from test.test_os import resource


ModelBase = declarative_base()

class Model(ModelBase):
	__tablename__ = 'model'
	
	handle = Column(String, primary_key=True)
	state = Column(String)
	watchdog_timer = Column(DateTime)
	created_at = Column(DateTime)
	
	def kick_watchdog(self, session):
		self.watchdog_timer = datetime.datetime.utcnow()
		session.commit()

	def set_inprogress(self, session):
		self.state = "INPROGRESS"
		session.commit()

	def set_done(self, session):
		self.state = "DONE"
		session.commit()

def define_model(model_name, dbengine):
	Base = declarative_base()
	
	bindings_tablename = '{}_bindings'.format(model_name)
	roles_tablename = '{}_roles'.format(model_name)
	permissions_tablename = '{}_permissions'.format(model_name)
	members_tablename = '{}_members'.format(model_name)
	resources_tablename = '{}_resources'.format(model_name)
	
	role_permissions_tablename = '{}_role_permissions'.format(model_name)
	binding_members_tablename = '{}_binding_members'.format(model_name)
	group_members_tablename = '{}_group_members'.format(model_name)

	role_permissions = Table(role_permissions_tablename, Base.metadata,
		Column('roles_name', ForeignKey('{}.name'.format(roles_tablename)), primary_key=True),
		Column('permissions_name', ForeignKey('{}.name'.format(permissions_tablename)), primary_key=True),
	)

	binding_members = Table(binding_members_tablename, Base.metadata,
		Column('bindings_id', ForeignKey('{}.id'.format(bindings_tablename)), primary_key=True),
		Column('members_name', ForeignKey('{}.name'.format(members_tablename)), primary_key=True),
	)

	group_members = Table(group_members_tablename, Base.metadata,
		Column('group_name', ForeignKey('{}.name'.format(members_tablename)), primary_key=True),
		Column('members_name', ForeignKey('{}.name'.format(members_tablename)), primary_key=True),
	)

	class Resource(Base):
		__tablename__ = resources_tablename

		full_name = Column(String, primary_key=True)
		name = Column(String)
		type = Column(String)

		parent_name = Column(String, ForeignKey('{}.name'.format(resources_tablename)))
		parent = relationship("Resource", remote_side=[name])
		bindings = relationship('Binding', back_populates="resource")

		def __repr__(self):
			return "<Resource(full_name='%s', type='%s')>" % (self.full_name, self.type)

	Resource.children = relationship(
		"Resource", order_by=Resource.name, back_populates="parent")

	class Member(Base):
		__tablename__ = members_tablename

		name = Column(String, primary_key=True)
		type = Column(String)

		parents  = relationship('Member', secondary=group_members,
			primaryjoin=name==group_members.c.group_name,
			secondaryjoin=name==group_members.c.members_name)

		children = relationship('Member', secondary=group_members,
			primaryjoin=name==group_members.c.members_name,
			secondaryjoin=name==group_members.c.group_name)

		bindings = relationship('Binding',
			secondary=binding_members,
			back_populates='members')

		def __repr__(self):
			return "<Member(name='%s', type='%s')>" % (self.name, self.type)


	class Binding(Base):
		__tablename__ = bindings_tablename

		id = Column(Integer, Sequence('{}_id_seq'.format(bindings_tablename)), primary_key=True)

		resource_name = Column(Integer, ForeignKey('{}.name'.format(resources_tablename)))
		role_name = Column(Integer, ForeignKey('{}.name'.format(roles_tablename)))

		resource = relationship('Resource', remote_side=[resource_name])
		role = relationship('Role', remote_side=[role_name])

		members = relationship('Member',
			secondary=binding_members,
			back_populates='bindings')

		def __repr__(self):
			return "<Binding(id='%s')>" % (self.id)

	class Role(Base):
		__tablename__ = roles_tablename

		name = Column(String, primary_key=True)
		permissions = relationship('Permission',
			secondary=role_permissions,
			back_populates='roles')

		def __repr__(self):
			return "<Role(name='%s')>" % (self.name)

	class Permission(Base):
		__tablename__ = permissions_tablename

		name = Column(String, primary_key=True)
		roles = relationship('Role',
			secondary=role_permissions,
			back_populates='permissions')

		def __repr__(self):
			return "<Permission(name='%s')>" % (self.name)

	class ModelAccess:
		TBL_BINDING = Binding
		TBL_MEMBER = Member
		TBL_PERMISSION = Permission
		TBL_ROLE = Role
		TBL_RESOURCE = Resource
		
		@staticmethod
		def deleteAll(engine):
			Binding.__table__.drop(engine)
			Member.__table__.drop(engine)
			Permission.__table__.drop(engine)
			Role.__table__.drop(engine)
			Resource.__table__.drop(engine)
			role_permissions.drop(engine)
			binding_members.drop(engine)
			group_members.drop(engine)

		@staticmethod	
		def addResource(session, name, parent=None):
			resource = Resource(full_name=name, name=name, type='test', parent=parent)
			session.add(resource)
			return resource

		@staticmethod
		def addRole(session, name, permissions=[]):
			role = Role(name=name, permissions=permissions)
			session.add(role)
			return role

		@staticmethod
		def addPermission(session, name, roles=[]):
			permission = Permission(name=name, roles=roles)
			session.add(permission)
			return permission

		@staticmethod
		def addBinding(session, resource, role, members):
			binding = Binding(resource=resource, role=role, members=members)
			session.add(binding)
			return binding

		@staticmethod
		def addMember(session, name, type, parents=[]):
			member = Member(name=name, type=type, parents=parents)
			session.add(member)
			return member

		@staticmethod
		def checkAccess(session, member_name, permission_name, resource_name):
			pass

		@staticmethod
		def reverseExpandMembers(session, member_names):
			members = session.query(Member).filter(Member.name.in_(member_names)).all()

			def isGroup(member):
				return member.type == 'group'

			member_set = set()
			new_member_set = set()

			def addToSets(members):
				for member in members:
					if member not in member_set:
						new_member_set.add(member)
						member_set.add(member)

			addToSets(members)
			while len(new_member_set) > 0:
				members_to_walk = new_member_set
				new_member_set = set()
				for member in members_to_walk:
					addToSets(member.parents)
			return member_set

		@staticmethod
		def expandMembers(session, member_names):
			members = session.query(Member).filter(Member.name.in_(member_names)).all()

			def isGroup(member):
				return member.type == 'group'

			group_set = set()
			non_group_set = set()
			new_group_set = set()

			def addToSets(members):
				for member in members:
					if isGroup(member):
						if member not in group_set:
							new_group_set.add(member)
						group_set.add(member)
					else:
						non_group_set.add(member)

			addToSets(members)

			while len(new_group_set) > 0:
				groups_to_walk = new_group_set
				new_group_set = set()
				for group in groups_to_walk:
					addToSets(group.children)

			return group_set.union(non_group_set)

		@staticmethod
		def findResourcePath(session, resource_name):
			resources = session.query(Resource).filter(Resource.name == resource_name).all()
			if len(resources) < 1:
				return []

			path = []

			resource = resources[0]

			path.append(resource)
			while resource.parent:
				resource = resource.parent
				path.append(resource)

			return path

		@staticmethod
		def getRolesByPermissionNames(session, permission_names):
			permission_set = set(permission_names)
			permissions = session.query(Permission).filter(Permission.name.in_(permission_set)).all()

			roles = set()
			for permission in permissions:
				for role in permission.roles:
					roles.add(role)

			result_set = set()
			for role in roles:
				role_permissions = set(map(lambda permission: permission.name, role.permissions))
				if permission_set.issubset(role_permissions):
					result_set.add(role)

			return result_set

		@staticmethod
		def getMember(session, name):
			return session.query(Member).filter(Member.name == name).all()

	Base.metadata.create_all(dbengine)
	return sessionmaker(bind=dbengine), ModelAccess

def undefine_model(sessionmaker, data_access):
	session = sessionmaker()
	data_access.deleteAll(session)

class ModelManager:
	def __init__(self, dbengine):
		self.engine = dbengine
		self.model_sessionmaker = self._create_model_session()
		self.sessionmakers = {}
	
	def _create_model_session(self):
		ModelBase.metadata.create_all(self.engine)
		return sessionmaker(bind=self.engine)
	
	def create(self):
		model_name = utils.generateModelHandle()
		session = self.model_sessionmaker()
		session.add(Model(handle=model_name, state="CREATED", created_at=datetime.datetime.utcnow(), watchdog_timer=datetime.datetime.utcnow()))
		session.commit()
		self.sessionmakers[model_name] = define_model(model_name, self.engine)
		return model_name

	def get(self, model):
		if not model in self.models():
			raise KeyError(model)
		
		try:
			return self.sessionmakers[model]
		except KeyError:
			self.sessionmakers[model] = define_model(model, self.engine)
			return self.sessionmakers[model]
	
	def delete(self, model_name):
		sessionmaker, data_access = self.sessionmakers[model_name]
		del self.sessionmakers[model_name]
		session = self.model_sessionmaker()
		session.query(Model).filter(Model.handle == model_name).delete()
		session.commit()
		del session
		data_access.deleteAll(self.engine)

	def models(self):
		session = self.model_sessionmaker()
		return map(lambda model: model.handle, session.query(Model).all())
	
	def model(self, model_name):
		session = self.model_sessionmaker()
		return session.query(Model).filter(Model.handle == model_name).one()

def session_creator(model_name, filename=None):
	if filename:
		engine = create_engine('sqlite:///%s'%filename)
	else:
		engine = create_engine('sqlite:///:memory:', echo=True)
		
	sessionmaker, data_access = define_model(model_name, engine)
	return sessionmaker, data_access

def createScenario(session, data_access):
	project = data_access.addResource(session, 'project')
	vm = data_access.addResource(session, 'vm1', project)
	db = data_access.addResource(session, 'db1', project)

	permission1 = data_access.addPermission(session, 'cloudsql.table.read')
	permission2 = data_access.addPermission(session, 'cloudsql.table.write')

	role1 = data_access.addRole(session, 'sqlreader', [permission1])
	role2 = data_access.addRole(session, 'sqlwriter', [permission1, permission2])

	group1 = data_access.addMember(session, 'group1', 'group')
	group2 = data_access.addMember(session, 'group2', 'group', [group1]) 

	member1 = data_access.addMember(session, 'felix', 'user', [group2])
	member2 = data_access.addMember(session, 'fooba', 'user', [group2])

	binding = data_access.addBinding(session, vm, role1, [group1])
	binding = data_access.addBinding(session, project, role2, [group2])
	session.commit()

def explainMemberHasAccessTo(session, data_access, member_names, expand_resources=False):
	if expand_resources:
		raise NotImplementedError()

	members = data_access.reverseExpandMembers(session, member_names)
	return session.query(data_access.TBL_RESOURCE).join(data_access.TBL_RESOURCE.bindings).join(data_access.TBL_BINDING.members).filter(data_access.TBL_MEMBER.name.in_(map(lambda m: m.name, members))).join(data_access.TBL_BINDING.role).all()

def explainHasAccessToResource(session, data_access, resource_name, permission_names, expand_groups=False):
	roles = data_access.getRolesByPermissionNames(session, permission_names)
	resources = data_access.findResourcePath(session, resource_name)
	bindings = session.query(data_access.TBL_BINDING).filter(data_access.TBL_BINDING.role_name.in_(map(lambda r: r.name, roles)), data_access.TBL_BINDING.resource_name.in_(map(lambda r: r.name, resources))).all()

	member_set = set()
	for binding in bindings:
		for member in binding.members:
			member_set.add(member)

	if not expand_groups:
		members = member_set
	else:
		members = data_access.expandMembers(session, map(lambda m: m.name, member_set))
	return members

def useScenario(session, data_access):
	print explainHasAccessToResource(session, data_access, 'vm1', ['cloudsql.table.read'], True)
	print explainHasAccessToResource(session, data_access, 'project', ['cloudsql.table.read'], False)
	print explainMemberHasAccessTo(session, data_access, ['group1'], False)

if __name__ == "__main__":
	engine = create_engine('sqlite:///:memory:', echo=True)
	model_manager = ModelManager(engine)
	
	model_name = model_manager.create()
	creator, data_access = model_manager.get(model_name)
	session = creator()
	createScenario(session, data_access)
	useScenario(session, data_access)
	
	model_name = model_manager.create()
	creator, data_access = model_manager.get(model_name)
	session = creator()
	createScenario(session, data_access)
	useScenario(session, data_access)
	
	model_manager.delete(model_name)
	print model_manager.models()
